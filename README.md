# stegohide

A command-line tool that encrypts a file and hides it inside a picture, video, or audio file. Only someone with the password can recover it.

Two implementations are included, sharing the exact same on-disk format — **a file hidden with one can be extracted with the other**:

- **`stegohide.py`** — Python, using Pillow/numpy for images and pydub/ffmpeg for audio.
- **`stegohide.c`** — C, using OpenSSL for crypto and shelling out to ffmpeg for all image/audio codec work (PNG pixels are piped through ffmpeg as raw RGB/RGBA; nothing reimplements PNG decoding by hand). WAV is read/written natively in C.

Everything below applies to both unless a section is specifically marked Python or C.

## Features

- **AES-256-GCM encryption** with a scrypt-derived key — your password never touches disk, and a wrong password is detected and rejected rather than silently producing garbage.
- **Two hiding modes**
  - `append` — works with *any* carrier file type (image, video, audio, anything). Fast and simple, but the hidden data is tacked onto the end of the file, so file size grows and the data doesn't survive re-encoding.
  - `lsb` (least-significant-bit) — embeds the encrypted bytes into the low bits of PNG pixels or WAV samples. Output is the same size as the carrier, and it's not obvious from a file-size glance that anything is hidden. Requires a lossless PNG/WAV carrier.
- **Built-in format conversion** — convert JPEG/BMP/GIF/WEBP/etc. to PNG, or MP3/FLAC/OGG/etc. to WAV, so you can use `lsb` mode with whatever media you already have.

## Requirements

### Python version

```
pip install cryptography pillow numpy
```

For audio format conversion (e.g. MP3 → WAV), also install:

```
pip install pydub
```

...and the `ffmpeg` binary (pydub shells out to it):

- **Linux:** `apt install ffmpeg`
- **macOS:** `brew install ffmpeg`
- **Windows:** `winget install ffmpeg`

If `ffmpeg`/`pydub` aren't installed, image conversion and both hiding modes still work — you'll only see an error if you specifically try to convert audio.

### C version

Needs a C compiler, OpenSSL's dev headers, and ffmpeg. See the **C version** section near the end of this README for build commands and details. Once built, run `./stegohide` (or `stegohide.exe` on Windows) in place of `python stegohide.py` in every example below — same subcommands, same flags.

## Usage

### Hide a file (append mode — any carrier type)

```
python stegohide.py hide cover.png secret.pdf -o out.png
```

### Hide a file (lsb mode — PNG/WAV only, less detectable)

```
python stegohide.py hide cover.png secret.pdf -o out.png -m lsb
```

If your carrier isn't already a PNG or WAV, add `--auto-convert` to convert it automatically first:

```
python stegohide.py hide photo.jpg secret.pdf -o out.png -m lsb --auto-convert
```

### Extract a hidden file

Use the same `-m`/`--method` you hid it with:

```
python stegohide.py extract out.png -d recovered/
python stegohide.py extract out.png -d recovered/ -m lsb
```

You'll be prompted for the password. A wrong password fails cleanly with `Wrong password or corrupted data.`

### Convert formats directly

```
python stegohide.py convert photo.jpg -o photo.png        # any image -> PNG
python stegohide.py convert song.mp3  -o song.wav          # any audio -> 16-bit WAV
```

Add `-t image` or `-t audio` to force the type instead of auto-detecting by extension.

## Common flags

| Flag | Applies to | Meaning |
|---|---|---|
| `-o`, `--output` | hide, convert | destination file |
| `-d`, `--dir` | extract | output directory for the recovered file |
| `-m`, `--method` | hide, extract | `append` (default) or `lsb` |
| `-f`, `--force` | all | overwrite existing output without asking |
| `--auto-convert` | hide | auto-convert a non-png/wav carrier before lsb hiding |

## How it works

1. Your secret file's name and bytes are packed together and encrypted with AES-256-GCM. The key comes from your password run through scrypt with a random salt, so the same password produces a different key every time.
2. **Append mode:** the encrypted blob plus a 16-byte footer (length + magic marker) is appended to the carrier's raw bytes. The carrier still opens/plays normally, since image, video, and audio formats all ignore trailing bytes.
3. **LSB mode:** the encrypted blob's bits replace the least-significant bit of each PNG pixel channel or each WAV audio sample. A 64-bit length header goes first so extraction knows how many bits to read back.

## Limitations

- **`append` mode data doesn't survive re-encoding.** Uploading to social media, converting formats, or re-saving will usually strip it.
- **`lsb` mode needs a lossless carrier.** JPEG/MP4/MP3 compression will destroy the hidden bits — that's why PNG/WAV are required, and why format conversion exists.
- **`lsb` mode is only built for PNG images and WAV audio**, not video — video carriers are only supported in `append` mode.
- **LSB steganography is statistically detectable.** Tools like `stegdetect` or histogram analysis can flag that *something* is likely hidden in a file, even though they can't read it without your password. The encryption is what actually protects the content; the hiding just avoids casual visual/manual inspection.
- **Capacity is limited** by the carrier's pixel/sample count — roughly 1 bit of hidden data per pixel channel (image) or per audio sample (audio). A 200×200 RGB PNG holds about 15 KB; scale up the carrier for bigger secrets.

## C version (`stegohide.c`)

A C port with the exact same on-disk format — a file hidden with one version extracts correctly with the other, for both `append` and `lsb` modes (PNG and WAV, RGB and RGBA).

**Design:** the C version does its own crypto (OpenSSL's AES-256-GCM + scrypt, not a reimplementation) and its own bit-level LSB embedding, but shells out to `ffmpeg`/`ffprobe` for image/audio codec work (PNG pixel decode/encode, and the `convert` command) rather than bundling an image/audio library. WAV read/write is done natively in C, no dependency needed there.

**Build:**
```
# Linux
sudo apt install libssl-dev ffmpeg
gcc -O2 -o stegohide stegohide.c -lssl -lcrypto

# macOS
brew install openssl ffmpeg
gcc -O2 -o stegohide stegohide.c -I$(brew --prefix openssl)/include -L$(brew --prefix openssl)/lib -lssl -lcrypto

# Windows (MSYS2/MinGW)
pacman -S mingw-w64-x86_64-openssl mingw-w64-x86_64-ffmpeg mingw-w64-x86_64-gcc
gcc -O2 -o stegohide.exe stegohide.c -lssl -lcrypto
```

**Usage** is identical to the Python version — same subcommands and flags:
```
./stegohide hide cover.png secret.pdf -o out.png -m lsb --auto-convert
./stegohide extract out.png -m lsb -d recovered/
./stegohide convert song.mp3 -o song.wav
```

**Differences from the Python version:**
- Password input isn't hidden/masked while typing (the Python version uses `getpass`; the C version reads a plain line from stdin). Fine for scripted/piped use, just know your password may echo to the terminal interactively.
- `ffmpeg`/`ffprobe` must be on `PATH` for `lsb` mode with PNG carriers and for the `convert` command. WAV `lsb` mode and `append` mode need no external tools at all.
- PNG channel handling matches Pillow's RGB-vs-RGBA split (alpha present → 4 channels, otherwise → 3), which is what makes cross-tool extraction work. Grayscale or palette PNGs aren't specially handled by either version — stick to RGB/RGBA sources, or run them through `convert` first.
- Built and tested on Linux: append mode, WAV `lsb` mode, PNG `lsb` mode (both RGB and RGBA carriers), `convert`, `--auto-convert`, wrong-password rejection, a carrier-too-small error, an 8 KB payload, and every combination of hiding with one implementation and extracting with the other — all verified working. The Windows/macOS build commands above are correct for the toolchains but weren't run on those platforms, so treat them as a solid starting point rather than guaranteed-exact.

Everything else — the encryption format, the LSB bit layout, the CLI flags — is identical on purpose, so the two implementations are drop-in compatible with each other's output.
