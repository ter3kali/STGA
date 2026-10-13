/*
 * stegohide.c - encrypt a file and hide it inside a picture or audio file.
 *
 * C port of the Python stegohide tool. Same on-disk format, so files hidden
 * with one version can be extracted with the other.
 *
 * Modes:
 *   append  Encrypted data is appended after the carrier's own bytes. Works
 *           with any carrier file type. Doesn't survive re-encoding.
 *   lsb     Encrypted data is embedded in the low bit of each byte of the
 *           carrier's raw pixel data (PNG) or sample data (WAV). Output is
 *           the same size as the carrier. Requires a lossless PNG/WAV
 *           carrier - use the 'convert' command first if yours isn't.
 *
 * The payload is always encrypted with AES-256-GCM, key derived from your
 * password with scrypt, regardless of which hiding mode you use.
 *
 * PNG/image pixel data and all audio *conversion* is done by shelling out to
 * ffmpeg, rather than reimplementing image/audio codecs in C. Only the
 * crypto and the bit-level hide/extract logic are native. This mirrors how
 * the Python version uses Pillow/pydub as its codec libraries - ffmpeg is
 * this version's.
 *
 * Build (Linux/macOS):
 *   sudo apt install libssl-dev ffmpeg        # or: brew install openssl ffmpeg
 *   gcc -O2 -o stegohide stegohide.c -lssl -lcrypto
 *
 * Build (Windows, MSYS2/MinGW):
 *   pacman -S mingw-w64-x86_64-openssl mingw-w64-x86_64-ffmpeg
 *   gcc -O2 -o stegohide.exe stegohide.c -lssl -lcrypto
 *
 * Requires ffmpeg on PATH at runtime for: lsb mode (both hide and extract,
 * to get/put raw pixels for PNG carriers), and the 'convert' command.
 * WAV lsb mode does NOT need ffmpeg - it's read/written natively in C.
 */

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>

#ifdef _WIN32
  #include <windows.h>
  #include <direct.h>
  #define POPEN _popen
  #define PCLOSE _pclose
  #define PATH_SEP '\\'
  #define POPEN_RMODE "rb"
  #define POPEN_WMODE "wb"
#else
  #include <unistd.h>
  #define POPEN popen
  #define PCLOSE pclose
  #define PATH_SEP '/'
  /* POSIX popen only accepts "r" or "w" - "rb"/"wb" make glibc's popen
   * return NULL (EINVAL). Binary-vs-text mode isn't a POSIX concept. */
  #define POPEN_RMODE "r"
  #define POPEN_WMODE "w"
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* ---------------------------------------------------------------------- */
/* Format constants - must match the Python version's on-disk format.     */
/* ---------------------------------------------------------------------- */

static const unsigned char MAGIC[8] = {'S','T','E','G','O','v','1', 0};
#define SALT_LEN   16
#define NONCE_LEN  12
#define TAG_LEN    16
#define FOOTER_LEN 16   /* 8-byte big-endian length + 8-byte magic */
#define LSB_LEN_BITS 64

/* scrypt params matching the Python Scrypt(n=2**15, r=8, p=1) */
#define SCRYPT_N (1 << 15)
#define SCRYPT_R 8
#define SCRYPT_P 1
#define SCRYPT_MAXMEM (256 * 1024 * 1024) /* generous cap so N/r/p above always fits */

/* ---------------------------------------------------------------------- */
/* Small helpers                                                          */
/* ---------------------------------------------------------------------- */

static void die(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

static void die_errno(const char *msg) {
    fprintf(stderr, "%s: %s\n", msg, strerror(errno));
    exit(1);
}

/* Read an entire file into a malloc'd buffer. Caller frees. */
static unsigned char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) die_errno("Could not open file");
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) die_errno("Could not read file size");
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc((size_t)sz ? (size_t)sz : 1);
    if (!buf) die("Out of memory");
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) die("Short read on file");
    *out_len = (size_t)sz;
    return buf;
}

static void write_file(const char *path, const unsigned char *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) die_errno("Could not open output file");
    if (len && fwrite(data, 1, len, f) != len) die("Short write on output file");
    fclose(f);
}

static int file_exists(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f) { fclose(f); return 1; }
    return 0;
}

static const char *ext_of(const char *path) {
    const char *dot = strrchr(path, '.');
    const char *slash = strrchr(path, PATH_SEP);
    if (!dot || (slash && dot < slash)) return "";
    return dot;
}

static int ext_ieq(const char *ext, const char *target) {
    size_t n = strlen(ext);
    if (n != strlen(target)) return 0;
    for (size_t i = 0; i < n; i++)
        if (tolower((unsigned char)ext[i]) != target[i]) return 0;
    return 1;
}

/* Basename without directory, used so an embedded file name can't escape
 * the output directory when extracting (mirrors Path(name).name in Python). */
static const char *base_name(const char *path) {
    const char *s1 = strrchr(path, '/');
    const char *s2 = strrchr(path, '\\');
    const char *s = s1 > s2 ? s1 : s2;
    return s ? s + 1 : path;
}

static void read_password(const char *prompt, char *out, size_t out_sz) {
    /* Simple portable password prompt. Not hiding terminal echo - documented
     * in the README as a known limitation of this C port vs. the Python
     * version's getpass(). Redirect from a file/pipe if you need silence. */
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(out, (int)out_sz, stdin)) die("Could not read password");
    size_t n = strlen(out);
    while (n > 0 && (out[n-1] == '\n' || out[n-1] == '\r')) out[--n] = 0;
}

/* ---------------------------------------------------------------------- */
/* Crypto: scrypt key derivation + AES-256-GCM, via OpenSSL EVP            */
/* ---------------------------------------------------------------------- */

static void derive_key(const char *password, const unsigned char *salt, unsigned char key[32]) {
    if (EVP_PBE_scrypt(password, strlen(password), salt, SALT_LEN,
                        SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_MAXMEM, key, 32) != 1) {
        die("scrypt key derivation failed");
    }
}

/* name_b || secret, little framing matching Python's encrypt():
 *   plaintext = u16_be(len(name)) + name_bytes + data
 * Returns a malloc'd buffer: salt(16) || nonce(12) || ciphertext || tag(16) */
static unsigned char *encrypt_blob(const char *name, const unsigned char *data, size_t data_len,
                                    const char *password, size_t *out_len) {
    size_t name_len = strlen(name);
    size_t pt_len = 2 + name_len + data_len;
    unsigned char *pt = malloc(pt_len);
    if (!pt) die("Out of memory");
    pt[0] = (unsigned char)((name_len >> 8) & 0xFF);
    pt[1] = (unsigned char)(name_len & 0xFF);
    memcpy(pt + 2, name, name_len);
    memcpy(pt + 2 + name_len, data, data_len);

    unsigned char salt[SALT_LEN], nonce[NONCE_LEN], key[32];
    if (RAND_bytes(salt, SALT_LEN) != 1 || RAND_bytes(nonce, NONCE_LEN) != 1)
        die("RNG failure");
    derive_key(password, salt, key);

    unsigned char *ct = malloc(pt_len);
    if (!ct) die("Out of memory");
    unsigned char tag[TAG_LEN];
    int len, ct_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) die("OpenSSL context alloc failed");
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) die("GCM init failed");
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL);
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) die("GCM key/iv set failed");
    if (EVP_EncryptUpdate(ctx, NULL, &len, MAGIC, sizeof(MAGIC)) != 1) die("GCM AAD failed");
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) die("GCM encrypt failed");
    ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct + ct_len, &len) != 1) die("GCM finalize failed");
    ct_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
    EVP_CIPHER_CTX_free(ctx);
    free(pt);

    size_t blob_len = SALT_LEN + NONCE_LEN + ct_len + TAG_LEN;
    unsigned char *blob = malloc(blob_len);
    if (!blob) die("Out of memory");
    memcpy(blob, salt, SALT_LEN);
    memcpy(blob + SALT_LEN, nonce, NONCE_LEN);
    memcpy(blob + SALT_LEN + NONCE_LEN, ct, ct_len);
    memcpy(blob + SALT_LEN + NONCE_LEN + ct_len, tag, TAG_LEN);
    free(ct);
    *out_len = blob_len;
    return blob;
}

/* Returns 1 and fills name_out / content_out on success (content malloc'd,
 * caller frees); returns 0 on wrong password or corrupted data. */
static int decrypt_blob(const unsigned char *blob, size_t blob_len, const char *password,
                         char name_out[256], unsigned char **content_out, size_t *content_len_out) {
    if (blob_len < (size_t)(SALT_LEN + NONCE_LEN + TAG_LEN)) return 0;
    const unsigned char *salt = blob;
    const unsigned char *nonce = blob + SALT_LEN;
    size_t ct_len = blob_len - SALT_LEN - NONCE_LEN - TAG_LEN;
    const unsigned char *ct = blob + SALT_LEN + NONCE_LEN;
    const unsigned char *tag = blob + SALT_LEN + NONCE_LEN + ct_len;

    unsigned char key[32];
    derive_key(password, salt, key);

    unsigned char *pt = malloc(ct_len ? ct_len : 1);
    if (!pt) die("Out of memory");
    int len, pt_len = 0, ok;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce);
    EVP_DecryptUpdate(ctx, NULL, &len, MAGIC, sizeof(MAGIC));
    EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len);
    pt_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag);
    ok = EVP_DecryptFinal_ex(ctx, pt + pt_len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ok != 1) { free(pt); return 0; } /* wrong password or corrupted data */
    pt_len += len;

    if (pt_len < 2) { free(pt); return 0; }
    size_t name_len = ((size_t)pt[0] << 8) | pt[1];
    if (name_len > 255 || (size_t)pt_len < 2 + name_len) { free(pt); return 0; }
    memcpy(name_out, pt + 2, name_len);
    name_out[name_len] = 0;

    size_t data_len = (size_t)pt_len - 2 - name_len;
    unsigned char *data = malloc(data_len ? data_len : 1);
    if (!data) die("Out of memory");
    memcpy(data, pt + 2 + name_len, data_len);
    free(pt);

    *content_out = data;
    *content_len_out = data_len;
    return 1;
}

/* ---------------------------------------------------------------------- */
/* append mode: hidden blob tacked onto the end, with a 16-byte footer.   */
/* ---------------------------------------------------------------------- */

static int has_payload_append(const unsigned char *data, size_t len) {
    return len >= FOOTER_LEN && memcmp(data + len - 8, MAGIC, 8) == 0;
}

static void footer_pack(unsigned char out[FOOTER_LEN], uint64_t blob_len) {
    for (int i = 0; i < 8; i++) out[i] = (unsigned char)(blob_len >> (56 - 8 * i));
    memcpy(out + 8, MAGIC, 8);
}

static uint64_t footer_unpack_len(const unsigned char *footer) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | footer[i];
    return v;
}

/* ---------------------------------------------------------------------- */
/* LSB mode: embed bits into the low bit of each byte of raw sample data. */
/* A 64-bit big-endian length header comes first, then the payload bits.  */
/* ---------------------------------------------------------------------- */

/* carrier_values is modified in place. n_values counts carrier *elements*,
 * each holding one LSB slot at byte offset (element_index * stride) - i.e.
 * element i's bit lives in carrier_values[i * stride].
 *
 * stride=1: every raw byte is its own element (used for PNG pixel bytes -
 *   matches Pillow/numpy's uint8 array, one bit per color channel byte).
 * stride=2: every OTHER byte is used (used for 16-bit PCM WAV samples -
 *   matches numpy's int16 array: modifying a 16-bit little-endian sample's
 *   lowest bit only ever touches its low-order byte, which sits at every
 *   even offset). This must match exactly for files hidden with one
 *   version of stegohide to extract correctly with the other. */
static void lsb_embed(unsigned char *carrier_values, size_t n_values, size_t stride,
                       const unsigned char *payload, size_t payload_len) {
    size_t need_bits = LSB_LEN_BITS + payload_len * 8;
    if (need_bits > n_values) die("Carrier is too small to hold this file in lsb mode.");

    size_t idx = 0;
    for (int i = LSB_LEN_BITS - 1; i >= 0; i--) {
        unsigned char bit = (unsigned char)((payload_len >> i) & 1);
        unsigned char *slot = carrier_values + idx * stride;
        *slot = (unsigned char)((*slot & ~1) | bit);
        idx++;
    }
    for (size_t b = 0; b < payload_len; b++) {
        for (int i = 7; i >= 0; i--) {
            unsigned char bit = (unsigned char)((payload[b] >> i) & 1);
            unsigned char *slot = carrier_values + idx * stride;
            *slot = (unsigned char)((*slot & ~1) | bit);
            idx++;
        }
    }
}

/* Returns malloc'd payload bytes (caller frees), or NULL if the carrier
 * doesn't contain a plausible length header. */
static unsigned char *lsb_extract(const unsigned char *carrier_values, size_t n_values, size_t stride,
                                   size_t *payload_len_out) {
    if (n_values < LSB_LEN_BITS) return NULL;
    uint64_t length = 0;
    for (size_t i = 0; i < LSB_LEN_BITS; i++)
        length = (length << 1) | (carrier_values[i * stride] & 1);

    uint64_t need_bits = (uint64_t)LSB_LEN_BITS + length * 8;
    if (need_bits > n_values) return NULL; /* bad password's blob length, or clean carrier */

    unsigned char *out = malloc((size_t)length ? (size_t)length : 1);
    if (!out) die("Out of memory");
    size_t idx = LSB_LEN_BITS;
    for (uint64_t b = 0; b < length; b++) {
        unsigned char byte = 0;
        for (int i = 0; i < 8; i++) {
            byte = (unsigned char)((byte << 1) | (carrier_values[idx * stride] & 1));
            idx++;
        }
        out[b] = byte;
    }
    *payload_len_out = (size_t)length;
    return out;
}

/* ---------------------------------------------------------------------- */
/* WAV: native read/write of 16-bit PCM, no external dependency.          */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint16_t num_channels;
    uint32_t sample_rate;
    uint16_t bits_per_sample;
    unsigned char *samples;   /* raw PCM data bytes */
    size_t samples_len;
} wav_t;

static uint32_t rd_u32le(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint16_t rd_u16le(const unsigned char *p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}
static void wr_u32le(unsigned char *p, uint32_t v) {
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF; p[2] = (v >> 16) & 0xFF; p[3] = (v >> 24) & 0xFF;
}
static void wr_u16le(unsigned char *p, uint16_t v) {
    p[0] = v & 0xFF; p[1] = (v >> 8) & 0xFF;
}

static wav_t wav_read(const char *path) {
    size_t len;
    unsigned char *data = read_file(path, &len);
    wav_t w = {0};
    if (len < 44 || memcmp(data, "RIFF", 4) != 0 || memcmp(data + 8, "WAVE", 4) != 0)
        die("Not a valid WAV file");

    size_t pos = 12;
    int have_fmt = 0;
    while (pos + 8 <= len) {
        char id[5] = {0};
        memcpy(id, data + pos, 4);
        uint32_t chunk_size = rd_u32le(data + pos + 4);
        size_t body = pos + 8;
        if (memcmp(id, "fmt ", 4) == 0) {
            if (body + 16 > len) die("Malformed WAV fmt chunk");
            uint16_t audio_format = rd_u16le(data + body);
            w.num_channels = rd_u16le(data + body + 2);
            w.sample_rate = rd_u32le(data + body + 4);
            w.bits_per_sample = rd_u16le(data + body + 14);
            if (audio_format != 1) die("Only PCM WAV files are supported");
            have_fmt = 1;
        } else if (memcmp(id, "data", 4) == 0) {
            if (body + chunk_size > len) die("Malformed WAV data chunk");
            w.samples = malloc(chunk_size ? chunk_size : 1);
            if (!w.samples) die("Out of memory");
            memcpy(w.samples, data + body, chunk_size);
            w.samples_len = chunk_size;
        }
        pos = body + chunk_size + (chunk_size & 1); /* chunks are word-aligned */
    }
    free(data);
    if (!have_fmt || !w.samples) die("WAV file missing fmt/data chunk");
    if (w.bits_per_sample != 16) die("Only 16-bit PCM WAV files are supported for lsb mode.");
    return w;
}

static void wav_write(const char *path, const wav_t *w) {
    uint32_t block_align = w->num_channels * (w->bits_per_sample / 8);
    uint32_t byte_rate = w->sample_rate * block_align;
    uint32_t data_size = (uint32_t)w->samples_len;
    uint32_t riff_size = 36 + data_size;

    unsigned char header[44];
    memcpy(header, "RIFF", 4);
    wr_u32le(header + 4, riff_size);
    memcpy(header + 8, "WAVE", 4);
    memcpy(header + 12, "fmt ", 4);
    wr_u32le(header + 16, 16);
    wr_u16le(header + 20, 1); /* PCM */
    wr_u16le(header + 22, w->num_channels);
    wr_u32le(header + 24, w->sample_rate);
    wr_u32le(header + 28, byte_rate);
    wr_u16le(header + 32, (uint16_t)block_align);
    wr_u16le(header + 34, w->bits_per_sample);
    memcpy(header + 36, "data", 4);
    wr_u32le(header + 40, data_size);

    FILE *f = fopen(path, "wb");
    if (!f) die_errno("Could not open output WAV");
    fwrite(header, 1, 44, f);
    if (data_size) fwrite(w->samples, 1, data_size, f);
    fclose(f);
}

/* ---------------------------------------------------------------------- */
/* PNG pixel access via ffmpeg pipes (decode to raw rgba, re-encode after).*/
/* ---------------------------------------------------------------------- */

/* Run a command, capturing stdout into a malloc'd buffer. */
static unsigned char *run_capture(const char *cmd, size_t *out_len) {
    FILE *p = POPEN(cmd, POPEN_RMODE);
    if (!p) die("Could not launch ffmpeg (is it installed and on PATH?)");
    size_t cap = 1 << 20, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) die("Out of memory");
    size_t n;
    while ((n = fread(buf + len, 1, cap - len, p)) > 0) {
        len += n;
        if (len == cap) {
            cap *= 2;
            unsigned char *nb = realloc(buf, cap);
            if (!nb) die("Out of memory");
            buf = nb;
        }
    }
    int rc = PCLOSE(p);
    if (rc != 0 || len == 0) die("ffmpeg command failed (see above) - is the input a valid/readable file?");
    *out_len = len;
    return buf;
}

/* Reads width, height, and whether the PNG has an alpha channel. Channel
 * count then follows the same rule Pillow uses (and the Python version
 * relies on): images with alpha get 4 channels (RGBA), everything else
 * gets 3 (RGB). Matching this is what lets a file hidden by one version
 * of stegohide extract correctly with the other. */
static void ffprobe_png_info(const char *path, int *w, int *h, int *channels) {
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "ffprobe -v error -select_streams v:0 -show_entries stream=width,height,pix_fmt "
        "-of csv=s=x:p=0 \"%s\"", path);
    FILE *p = POPEN(cmd, "r");
    if (!p) die("Could not launch ffprobe (is ffmpeg installed and on PATH?)");
    char line[256] = {0};
    if (!fgets(line, sizeof(line), p)) { PCLOSE(p); die("Could not read image info"); }
    PCLOSE(p);

    /* csv output is "WIDTHxHEIGHTxPIX_FMT", e.g. "200x200x rgb24" */
    char pix_fmt[128] = {0};
    char *tok = strtok(line, "x\r\n");
    if (!tok) die("Could not parse image width");
    *w = atoi(tok);
    tok = strtok(NULL, "x\r\n");
    if (!tok) die("Could not parse image height");
    *h = atoi(tok);
    tok = strtok(NULL, "x\r\n");
    if (tok) snprintf(pix_fmt, sizeof(pix_fmt), "%s", tok);

    /* known alpha-carrying pixel formats ffmpeg reports for PNG */
    *channels = (strstr(pix_fmt, "rgba") || strstr(pix_fmt, "bgra") ||
                 strstr(pix_fmt, "ya8") || strstr(pix_fmt, "ya16") ||
                 strstr(pix_fmt, "pal8")) ? 4 : 3;
}

/* Decode a PNG to raw pixel bytes via ffmpeg. Returns malloc'd buffer of
 * w*h*channels bytes; *channels is set to 3 (rgb24) or 4 (rgba). */
static unsigned char *png_decode(const char *path, int *w, int *h, int *channels) {
    ffprobe_png_info(path, w, h, channels);
    const char *pix_fmt = (*channels == 4) ? "rgba" : "rgb24";
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "ffmpeg -nostdin -v error -i \"%s\" -f rawvideo -pix_fmt %s -", path, pix_fmt);
    size_t len;
    unsigned char *buf = run_capture(cmd, &len);
    size_t expect = (size_t)(*w) * (*h) * (*channels);
    if (len != expect) die("Unexpected amount of pixel data decoded from PNG");
    return buf;
}

/* Re-encode raw pixel bytes back to a PNG via ffmpeg. */
static void png_encode(const char *path, const unsigned char *pixels, int w, int h, int channels) {
    const char *pix_fmt = (channels == 4) ? "rgba" : "rgb24";
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "ffmpeg -nostdin -v error -y -f rawvideo -pix_fmt %s -s %dx%d -i - \"%s\"",
        pix_fmt, w, h, path);
    FILE *p = POPEN(cmd, POPEN_WMODE);
    if (!p) die("Could not launch ffmpeg (is it installed and on PATH?)");
    size_t total = (size_t)w * h * channels;
    if (fwrite(pixels, 1, total, p) != total) die("Short write piping pixels to ffmpeg");
    int rc = PCLOSE(p);
    if (rc != 0) die("ffmpeg failed to encode PNG");
}

/* ---------------------------------------------------------------------- */
/* High-level lsb hide/extract dispatch for png vs wav                    */
/* ---------------------------------------------------------------------- */

static void lsb_hide_png(const char *carrier, const unsigned char *blob, size_t blob_len, const char *out) {
    int w, h, channels;
    unsigned char *pixels = png_decode(carrier, &w, &h, &channels);
    size_t n = (size_t)w * h * channels; /* one element per raw byte, stride 1 */
    lsb_embed(pixels, n, 1, blob, blob_len);
    png_encode(out, pixels, w, h, channels);
    free(pixels);
}

static unsigned char *lsb_extract_png(const char *stego, size_t *out_len) {
    int w, h, channels;
    unsigned char *pixels = png_decode(stego, &w, &h, &channels);
    size_t n = (size_t)w * h * channels;
    unsigned char *payload = lsb_extract(pixels, n, 1, out_len);
    free(pixels);
    if (!payload) die("No valid hidden data found (bad password or clean carrier).");
    return payload;
}

static void lsb_hide_wav(const char *carrier, const unsigned char *blob, size_t blob_len, const char *out) {
    wav_t w = wav_read(carrier);
    size_t n_samples = w.samples_len / 2; /* one element per 16-bit sample, stride 2 */
    lsb_embed(w.samples, n_samples, 2, blob, blob_len);
    wav_write(out, &w);
    free(w.samples);
}

static unsigned char *lsb_extract_wav(const char *stego, size_t *out_len) {
    wav_t w = wav_read(stego);
    size_t n_samples = w.samples_len / 2;
    unsigned char *payload = lsb_extract(w.samples, n_samples, 2, out_len);
    free(w.samples);
    if (!payload) die("No valid hidden data found (bad password or clean carrier).");
    return payload;
}

/* ---------------------------------------------------------------------- */
/* Format conversion: any image -> PNG, any audio -> 16-bit WAV, via ffmpeg*/
/* ---------------------------------------------------------------------- */

static const char *IMAGE_EXTS[] = {".jpg",".jpeg",".bmp",".gif",".tiff",".tif",".webp",".heic",".png",0};
static const char *AUDIO_EXTS[] = {".mp3",".flac",".ogg",".m4a",".aac",".wma",".aiff",".wav",0};

static int ext_in_list(const char *ext, const char **list) {
    for (int i = 0; list[i]; i++) if (ext_ieq(ext, list[i])) return 1;
    return 0;
}

static void run_or_die(const char *cmd) {
    int rc = system(cmd);
    if (rc != 0) die("ffmpeg command failed - check the path/format and that ffmpeg is installed.");
}

static void convert_image_to_png(const char *src, const char *dst) {
    char cmd[2048];
    snprintf(cmd, sizeof(cmd), "ffmpeg -nostdin -v error -y -i \"%s\" \"%s\"", src, dst);
    run_or_die(cmd);
}

static void convert_audio_to_wav(const char *src, const char *dst) {
    /* Normalize to 16-bit PCM mono 44100Hz, matching the Python version's
     * default pydub conversion target - that's what lsb mode expects. */
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "ffmpeg -nostdin -v error -y -i \"%s\" -ar 44100 -ac 1 -sample_fmt s16 \"%s\"", src, dst);
    run_or_die(cmd);
}

static void convert_to_lossless(const char *src, const char *dst) {
    const char *e = ext_of(src);
    if (ext_in_list(e, IMAGE_EXTS)) convert_image_to_png(src, dst);
    else if (ext_in_list(e, AUDIO_EXTS)) convert_audio_to_wav(src, dst);
    else die("Don't know how to convert this file type (not a recognized image/audio extension).");
}

/* ---------------------------------------------------------------------- */
/* Commands                                                                */
/* ---------------------------------------------------------------------- */

typedef struct {
    const char *method;    /* "append" or "lsb" */
    int force;
    int auto_convert;
} opts_t;

static void cmd_hide(const char *carrier_path, const char *secret_path, const char *out_path, opts_t *o) {
    if (file_exists(out_path) && !o->force)
        die("Output file exists (use --force to overwrite).");

    size_t secret_len;
    unsigned char *secret = read_file(secret_path, &secret_len);

    char pw1[256], pw2[256];
    read_password("Password: ", pw1, sizeof(pw1));
    read_password("Confirm password: ", pw2, sizeof(pw2));
    if (strcmp(pw1, pw2) != 0) die("Passwords do not match.");

    size_t blob_len;
    unsigned char *blob = encrypt_blob(base_name(secret_path), secret, secret_len, pw1, &blob_len);
    free(secret);

    if (strcmp(o->method, "lsb") == 0) {
        const char *ext = ext_of(carrier_path);
        char tmp_path[1024];
        const char *actual_carrier = carrier_path;
        int used_tmp = 0;

        if (!ext_ieq(ext, ".png") && !ext_ieq(ext, ".wav")) {
            if (!o->auto_convert) {
                fprintf(stderr,
                    "lsb mode needs a .png or .wav carrier, got '%s'. "
                    "Re-run with --auto-convert, or convert it first with the 'convert' command.\n", ext);
                exit(1);
            }
            const char *new_ext = ext_in_list(ext, IMAGE_EXTS) ? ".png" : ".wav";
            snprintf(tmp_path, sizeof(tmp_path), "%s.tmp_converted%s", out_path, new_ext);
            printf("Converting %s -> %s first...\n", carrier_path, tmp_path);
            convert_to_lossless(carrier_path, tmp_path);
            actual_carrier = tmp_path;
            used_tmp = 1;
        }

        if (ext_ieq(ext_of(actual_carrier), ".png"))
            lsb_hide_png(actual_carrier, blob, blob_len, out_path);
        else
            lsb_hide_wav(actual_carrier, blob, blob_len, out_path);

        if (used_tmp) remove(tmp_path);
        printf("Hidden %zu bytes inside %s (lsb mode)\n", blob_len, out_path);
    } else {
        size_t carrier_len;
        unsigned char *carrier = read_file(carrier_path, &carrier_len);
        if (has_payload_append(carrier, carrier_len))
            die("Carrier already contains a hidden file.");

        unsigned char footer[FOOTER_LEN];
        footer_pack(footer, blob_len);

        FILE *f = fopen(out_path, "wb");
        if (!f) die_errno("Could not open output file");
        fwrite(carrier, 1, carrier_len, f);
        fwrite(blob, 1, blob_len, f);
        fwrite(footer, 1, FOOTER_LEN, f);
        fclose(f);
        free(carrier);
        printf("Hidden %zu bytes inside %s (append mode)\n", secret_len, out_path);
    }
    free(blob);
}

static void cmd_extract(const char *stego_path, const char *out_dir, opts_t *o) {
    unsigned char *blob;
    size_t blob_len;
    int blob_is_owned = 1;

    if (strcmp(o->method, "lsb") == 0) {
        const char *ext = ext_of(stego_path);
        if (ext_ieq(ext, ".png"))
            blob = lsb_extract_png(stego_path, &blob_len);
        else if (ext_ieq(ext, ".wav"))
            blob = lsb_extract_wav(stego_path, &blob_len);
        else
            die("lsb mode only supports .png and .wav carriers.");
    } else {
        size_t data_len;
        unsigned char *data = read_file(stego_path, &data_len);
        if (!has_payload_append(data, data_len)) die("No hidden file found.");
        uint64_t len64 = footer_unpack_len(data + data_len - FOOTER_LEN);
        if (len64 > data_len - FOOTER_LEN) die("Hidden data is corrupted.");
        blob_len = (size_t)len64;
        blob = malloc(blob_len ? blob_len : 1);
        if (!blob) die("Out of memory");
        memcpy(blob, data + data_len - FOOTER_LEN - blob_len, blob_len);
        free(data);
    }

    char pw[256];
    read_password("Password: ", pw, sizeof(pw));

    char name[256];
    unsigned char *content;
    size_t content_len;
    int ok = decrypt_blob(blob, blob_len, pw, name, &content, &content_len);
    if (blob_is_owned) free(blob);
    if (!ok) die("Wrong password or corrupted data.");

    /* Make the output directory if needed (single-level is enough here). */
#ifdef _WIN32
    _mkdir(out_dir);
#else
    char mkcmd[1024];
    snprintf(mkcmd, sizeof(mkcmd), "mkdir -p \"%s\"", out_dir);
    if (system(mkcmd) != 0) die("Could not create output directory");
#endif

    char dest[1024];
    snprintf(dest, sizeof(dest), "%s%c%s", out_dir, PATH_SEP, base_name(name));
    if (file_exists(dest) && !o->force) die("Destination file exists (use --force to overwrite).");
    write_file(dest, content, content_len);
    printf("Extracted %s (%zu bytes)\n", dest, content_len);
    free(content);
}

static void cmd_convert(const char *input, const char *output, const char *type, int force) {
    if (file_exists(output) && !force) die("Output file exists (use --force to overwrite).");
    if (strcmp(type, "image") == 0) convert_image_to_png(input, output);
    else if (strcmp(type, "audio") == 0) convert_audio_to_wav(input, output);
    else convert_to_lossless(input, output);
    printf("Converted %s -> %s\n", input, output);
}

/* ---------------------------------------------------------------------- */
/* CLI                                                                     */
/* ---------------------------------------------------------------------- */

static void usage(void) {
    fprintf(stderr,
        "stegohide - hide an encrypted file inside an image or audio file\n\n"
        "Usage:\n"
        "  stegohide hide    <carrier> <secret> -o <output> [-m append|lsb] [--auto-convert] [-f]\n"
        "  stegohide extract <stego>            -d <dir>    [-m append|lsb] [-f]\n"
        "  stegohide convert <input>             -o <output> [-t image|audio|auto] [-f]\n\n"
        "Options:\n"
        "  -o, --output   output file (hide, convert)\n"
        "  -d, --dir      output directory, default '.' (extract)\n"
        "  -m, --method   append (default) or lsb (hide, extract)\n"
        "  -t, --type     image, audio, or auto (default) (convert)\n"
        "  --auto-convert automatically convert a non-png/wav carrier before lsb hide\n"
        "  -f, --force    overwrite existing output without asking\n");
}

static const char *get_opt_val(int argc, char **argv, int *i, const char *long_name, const char *short_name) {
    if (strcmp(argv[*i], long_name) == 0 || strcmp(argv[*i], short_name) == 0) {
        if (*i + 1 >= argc) { fprintf(stderr, "Missing value for %s\n", argv[*i]); exit(1); }
        (*i)++;
        return argv[*i];
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 1; }
    const char *cmd = argv[1];

    if (strcmp(cmd, "hide") == 0) {
        const char *carrier = NULL, *secret = NULL, *output = NULL;
        opts_t o = { "append", 0, 0 };
        int pos = 0;
        for (int i = 2; i < argc; i++) {
            const char *v;
            if ((v = get_opt_val(argc, argv, &i, "--output", "-o"))) { output = v; continue; }
            if ((v = get_opt_val(argc, argv, &i, "--method", "-m"))) { o.method = v; continue; }
            if (strcmp(argv[i], "--force") == 0 || strcmp(argv[i], "-f") == 0) { o.force = 1; continue; }
            if (strcmp(argv[i], "--auto-convert") == 0) { o.auto_convert = 1; continue; }
            if (pos == 0) { carrier = argv[i]; pos++; }
            else if (pos == 1) { secret = argv[i]; pos++; }
            else { fprintf(stderr, "Unexpected argument: %s\n", argv[i]); return 1; }
        }
        if (!carrier || !secret || !output) { usage(); return 1; }
        if (strcmp(o.method, "append") != 0 && strcmp(o.method, "lsb") != 0)
            die("--method must be 'append' or 'lsb'");
        cmd_hide(carrier, secret, output, &o);

    } else if (strcmp(cmd, "extract") == 0) {
        const char *stego = NULL, *dir = ".";
        opts_t o = { "append", 0, 0 };
        int pos = 0;
        for (int i = 2; i < argc; i++) {
            const char *v;
            if ((v = get_opt_val(argc, argv, &i, "--dir", "-d"))) { dir = v; continue; }
            if ((v = get_opt_val(argc, argv, &i, "--method", "-m"))) { o.method = v; continue; }
            if (strcmp(argv[i], "--force") == 0 || strcmp(argv[i], "-f") == 0) { o.force = 1; continue; }
            if (pos == 0) { stego = argv[i]; pos++; }
            else { fprintf(stderr, "Unexpected argument: %s\n", argv[i]); return 1; }
        }
        if (!stego) { usage(); return 1; }
        if (strcmp(o.method, "append") != 0 && strcmp(o.method, "lsb") != 0)
            die("--method must be 'append' or 'lsb'");
        cmd_extract(stego, dir, &o);

    } else if (strcmp(cmd, "convert") == 0) {
        const char *input = NULL, *output = NULL, *type = "auto";
        int force = 0, pos = 0;
        for (int i = 2; i < argc; i++) {
            const char *v;
            if ((v = get_opt_val(argc, argv, &i, "--output", "-o"))) { output = v; continue; }
            if ((v = get_opt_val(argc, argv, &i, "--type", "-t"))) { type = v; continue; }
            if (strcmp(argv[i], "--force") == 0 || strcmp(argv[i], "-f") == 0) { force = 1; continue; }
            if (pos == 0) { input = argv[i]; pos++; }
            else { fprintf(stderr, "Unexpected argument: %s\n", argv[i]); return 1; }
        }
        if (!input || !output) { usage(); return 1; }
        if (strcmp(type, "image") != 0 && strcmp(type, "audio") != 0 && strcmp(type, "auto") != 0)
            die("--type must be 'image', 'audio', or 'auto'");
        cmd_convert(input, output, type, force);

    } else {
        usage();
        return 1;
    }
    return 0;
}
