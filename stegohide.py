#!/usr/bin/env python3
"""stegohide - encrypt a file and hide it inside a picture, video or audio file.

Two modes:
  append  Encrypted data is appended after the carrier's own data. Works with
          any file type, survives nothing (re-encoding/re-saving strips it).
  lsb     Encrypted data is embedded in the low bits of PNG pixels or WAV
          samples. Carrier must stay a lossless PNG/WAV. Harder to spot by
          just eyeballing file size, since the output is the same size as
          a plain re-save of the carrier.

The payload itself is always encrypted with AES-256-GCM using a key derived
from your password (scrypt), so without the password it is unreadable either way.

Usage:
    python stegohide.py hide    cover.png secret.pdf -o cover_out.png
    python stegohide.py extract cover_out.png -d recovered/
    python stegohide.py hide    cover.png secret.pdf -o cover_out.png -m lsb
    python stegohide.py extract cover_out.png -d recovered/ -m lsb

Requires: pip install cryptography
For lsb mode with images: pip install pillow numpy
For lsb mode with wav audio: numpy only (wave is in the standard library)
"""
import argparse
import getpass
import io
import os
import struct
import sys
import wave
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"STEGOv1\x00"            # 8 bytes, marks the end of a hidden payload
FOOTER = struct.Struct(">Q8s")    # payload length + magic = 16 bytes
SALT_LEN = 16
NONCE_LEN = 12
LSB_LEN_BITS = 64                 # bits used to store the LSB payload length


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def encrypt(name: str, data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    name_b = name.encode("utf-8")
    plaintext = struct.pack(">H", len(name_b)) + name_b + data
    ct = AESGCM(derive_key(password, salt)).encrypt(nonce, plaintext, MAGIC)
    return salt + nonce + ct


def decrypt(blob: bytes, password: str) -> tuple[str, bytes]:
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN + NONCE_LEN]
    ct = blob[SALT_LEN + NONCE_LEN:]
    plaintext = AESGCM(derive_key(password, salt)).decrypt(nonce, ct, MAGIC)
    (name_len,) = struct.unpack(">H", plaintext[:2])
    name = plaintext[2:2 + name_len].decode("utf-8")
    return name, plaintext[2 + name_len:]


def has_payload(data: bytes) -> bool:
    return len(data) >= FOOTER.size and data[-8:] == MAGIC


# ---------------------------------------------------------------------------
# LSB (least-significant-bit) mode: hide bits inside pixel/sample values.
# ---------------------------------------------------------------------------

def _bytes_to_bits(data: bytes):
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1


def _bits_to_bytes(bits) -> bytes:
    out = bytearray()
    cur = 0
    n = 0
    for b in bits:
        cur = (cur << 1) | b
        n += 1
        if n == 8:
            out.append(cur)
            cur = 0
            n = 0
    return bytes(out)


def _lsb_capacity_bits(n_values: int) -> int:
    return n_values  # 1 bit per channel/sample value


def _lsb_embed(flat_values, payload: bytes):
    """Return a copy of flat_values (numpy array) with payload's bits written
    into the least significant bit of each element, length-prefixed."""
    import numpy as np

    header_bits = [(len(payload) >> i) & 1 for i in range(LSB_LEN_BITS - 1, -1, -1)]
    bits = header_bits + list(_bytes_to_bits(payload))
    if len(bits) > _lsb_capacity_bits(flat_values.size):
        raise ValueError("Carrier is too small to hold this file in lsb mode.")
    bits_arr = np.array(bits, dtype=flat_values.dtype)
    out = flat_values.copy()
    out[:len(bits)] = (out[:len(bits)] & ~np.array(1, dtype=out.dtype)) | bits_arr
    return out


def _lsb_extract(flat_values) -> bytes:
    import numpy as np

    if flat_values.size < LSB_LEN_BITS:
        raise ValueError("Carrier too small to contain a header.")
    header_bits = (flat_values[:LSB_LEN_BITS] & 1).tolist()
    length = 0
    for b in header_bits:
        length = (length << 1) | int(b)
    needed = LSB_LEN_BITS + length * 8
    if needed > flat_values.size:
        raise ValueError("No valid hidden data found (bad password or clean carrier).")
    payload_bits = (flat_values[LSB_LEN_BITS:needed] & 1).tolist()
    return _bits_to_bytes(payload_bits)


def _lsb_hide_png(carrier_path: Path, blob: bytes, out_path: Path):
    from PIL import Image
    import numpy as np

    img = Image.open(carrier_path)
    img = img.convert("RGBA") if img.mode in ("P", "LA") else img
    arr = np.array(img)
    flat = arr.reshape(-1)
    new_flat = _lsb_embed(flat, blob)
    new_arr = new_flat.reshape(arr.shape)
    Image.fromarray(new_arr, mode=img.mode if img.mode in ("RGB", "RGBA", "L") else "RGBA").save(out_path, "PNG")


def _lsb_extract_png(stego_path: Path) -> bytes:
    from PIL import Image
    import numpy as np

    img = Image.open(stego_path)
    arr = np.array(img)
    flat = arr.reshape(-1)
    return _lsb_extract(flat)


def _lsb_hide_wav(carrier_path: Path, blob: bytes, out_path: Path):
    import numpy as np

    with wave.open(str(carrier_path), "rb") as wf:
        params = wf.getparams()
        frames = wf.readframes(wf.getnframes())
    if params.sampwidth != 2:
        raise ValueError("Only 16-bit PCM WAV files are supported for lsb mode.")
    samples = np.frombuffer(frames, dtype=np.int16)
    new_samples = _lsb_embed(samples, blob)
    with wave.open(str(out_path), "wb") as wf:
        wf.setparams(params)
        wf.writeframes(new_samples.tobytes())


def _lsb_extract_wav(stego_path: Path) -> bytes:
    import numpy as np

    with wave.open(str(stego_path), "rb") as wf:
        frames = wf.readframes(wf.getnframes())
    samples = np.frombuffer(frames, dtype=np.int16)
    return _lsb_extract(samples)


def _lsb_dispatch(path: Path):
    ext = path.suffix.lower()
    if ext == ".png":
        return _lsb_hide_png, _lsb_extract_png
    if ext == ".wav":
        return _lsb_hide_wav, _lsb_extract_wav
    raise ValueError("lsb mode only supports .png and .wav carriers.")


# ---------------------------------------------------------------------------
# Format conversion: any image -> PNG (Pillow), any audio -> WAV (pydub/ffmpeg).
# lsb mode needs a lossless carrier, so converting a JPEG/MP3/etc. first
# avoids "Only 16-bit PCM WAV" / palette / compression errors.
# ---------------------------------------------------------------------------

IMAGE_EXTS = {".jpg", ".jpeg", ".bmp", ".gif", ".tiff", ".tif", ".webp", ".heic", ".png"}
AUDIO_EXTS = {".mp3", ".flac", ".ogg", ".m4a", ".aac", ".wma", ".aiff", ".wav"}


def convert_image_to_png(src: Path, dst: Path):
    from PIL import Image

    img = Image.open(src)
    # Flatten anything with an alpha/palette quirk into plain RGB(A) so the
    # lsb pixel math later always sees a predictable dtype/shape.
    if img.mode == "P":
        img = img.convert("RGBA") if "transparency" in img.info else img.convert("RGB")
    elif img.mode not in ("RGB", "RGBA", "L"):
        img = img.convert("RGB")
    img.save(dst, "PNG")


def convert_audio_to_wav(src: Path, dst: Path, sample_width=2, frame_rate=44100, channels=1):
    try:
        from pydub import AudioSegment
    except ImportError:
        raise RuntimeError(
            "Audio conversion needs pydub and the ffmpeg binary: "
            "pip install pydub, then install ffmpeg (e.g. 'winget install ffmpeg' "
            "on Windows, 'apt install ffmpeg' on Linux, 'brew install ffmpeg' on Mac)."
        )
    try:
        audio = AudioSegment.from_file(src)
    except Exception as e:
        raise RuntimeError(f"Could not read {src} (is ffmpeg installed?): {e}")
    # Normalize to 16-bit PCM mono by default, matching what hide --method lsb expects.
    audio = audio.set_sample_width(sample_width).set_frame_rate(frame_rate).set_channels(channels)
    audio.export(dst, format="wav")


def convert_to_lossless(src: Path, dst: Path):
    """Auto-detect image vs audio by extension and convert to PNG/WAV."""
    ext = src.suffix.lower()
    if ext in IMAGE_EXTS:
        convert_image_to_png(src, dst)
    elif ext in AUDIO_EXTS:
        convert_audio_to_wav(src, dst)
    else:
        raise ValueError(f"Don't know how to convert '{ext}' files (not a recognized image/audio type).")


def cmd_convert(args):
    src = Path(args.input)
    dst = Path(args.output)
    if dst.exists() and not args.force:
        sys.exit(f"{dst} exists (use --force to overwrite).")
    try:
        if args.type == "image":
            convert_image_to_png(src, dst)
        elif args.type == "audio":
            convert_audio_to_wav(src, dst)
        else:
            convert_to_lossless(src, dst)
    except Exception as e:
        sys.exit(f"Conversion failed: {e}")
    print(f"Converted {src} -> {dst}")


def cmd_hide(args):
    carrier_path = Path(args.carrier)
    secret_path = Path(args.secret)
    secret = secret_path.read_bytes()
    out = Path(args.output)
    if out.exists() and not args.force:
        sys.exit(f"{out} exists (use --force to overwrite).")

    pw = getpass.getpass("Password: ")
    if pw != getpass.getpass("Confirm password: "):
        sys.exit("Passwords do not match.")
    blob = encrypt(secret_path.name, secret, pw)

    if args.method == "lsb":
        tmp_converted = None
        try:
            if carrier_path.suffix.lower() not in (".png", ".wav"):
                if not args.auto_convert:
                    sys.exit(
                        f"lsb mode needs a .png or .wav carrier, got '{carrier_path.suffix}'. "
                        f"Re-run with --auto-convert, or convert it first with the 'convert' subcommand."
                    )
                tmp_converted = out.with_name(f".tmp_converted_{out.name}")
                tmp_converted = tmp_converted.with_suffix(
                    ".png" if carrier_path.suffix.lower() in IMAGE_EXTS else ".wav"
                )
                print(f"Converting {carrier_path} -> {tmp_converted} first...")
                convert_to_lossless(carrier_path, tmp_converted)
                carrier_path = tmp_converted

            hide_fn, _ = _lsb_dispatch(carrier_path)
            hide_fn(carrier_path, blob, out)
        except Exception as e:
            sys.exit(f"lsb hide failed: {e}")
        finally:
            if tmp_converted and tmp_converted.exists():
                tmp_converted.unlink()
        print(f"Hidden {len(secret):,} bytes inside {out} (lsb mode)")
    else:
        carrier = carrier_path.read_bytes()
        if has_payload(carrier):
            sys.exit("Carrier already contains a hidden file.")
        out.write_bytes(carrier + blob + FOOTER.pack(len(blob), MAGIC))
        print(f"Hidden {len(secret):,} bytes inside {out} (append mode)")


def cmd_extract(args):
    stego_path = Path(args.stego)

    if args.method == "lsb":
        try:
            _, extract_fn = _lsb_dispatch(stego_path)
            blob = extract_fn(stego_path)
        except Exception as e:
            sys.exit(f"lsb extract failed: {e}")
    else:
        data = stego_path.read_bytes()
        if not has_payload(data):
            sys.exit("No hidden file found.")
        (blob_len, _) = FOOTER.unpack(data[-FOOTER.size:])
        if blob_len > len(data) - FOOTER.size:
            sys.exit("Hidden data is corrupted.")
        blob = data[-FOOTER.size - blob_len:-FOOTER.size]

    pw = getpass.getpass("Password: ")
    try:
        name, content = decrypt(blob, pw)
    except InvalidTag:
        sys.exit("Wrong password or corrupted data.")

    outdir = Path(args.dir)
    outdir.mkdir(parents=True, exist_ok=True)
    dest = outdir / Path(name).name          # strip any path components
    if dest.exists() and not args.force:
        sys.exit(f"{dest} exists (use --force to overwrite).")
    dest.write_bytes(content)
    print(f"Extracted {dest} ({len(content):,} bytes)")


def main():
    p = argparse.ArgumentParser(description="Hide encrypted files inside media files.")
    sub = p.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("hide", help="hide a file inside a carrier")
    h.add_argument("carrier", help="image/video/audio file to hide data in")
    h.add_argument("secret", help="file to hide")
    h.add_argument("-o", "--output", required=True, help="output file")
    h.add_argument("-f", "--force", action="store_true")
    h.add_argument("-m", "--method", choices=["append", "lsb"], default="append",
                   help="append: works with any file type. lsb: hides bits in "
                        "PNG pixels or WAV samples, output same size as carrier (default: append)")
    h.add_argument("--auto-convert", action="store_true",
                   help="with -m lsb, automatically convert a non-png/wav carrier first")
    h.set_defaults(func=cmd_hide)

    e = sub.add_parser("extract", help="recover a hidden file")
    e.add_argument("stego", help="file containing hidden data")
    e.add_argument("-d", "--dir", default=".", help="output directory")
    e.add_argument("-f", "--force", action="store_true")
    e.add_argument("-m", "--method", choices=["append", "lsb"], default="append",
                   help="must match the method used when hiding (default: append)")
    e.set_defaults(func=cmd_extract)

    c = sub.add_parser("convert", help="convert an image to PNG or audio to WAV")
    c.add_argument("input", help="source image or audio file")
    c.add_argument("-o", "--output", required=True, help="destination .png or .wav file")
    c.add_argument("-t", "--type", choices=["image", "audio", "auto"], default="auto",
                   help="force image or audio conversion, or auto-detect by extension (default: auto)")
    c.add_argument("-f", "--force", action="store_true")
    c.set_defaults(func=cmd_convert)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
