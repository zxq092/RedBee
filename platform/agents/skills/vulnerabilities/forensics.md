---
name: forensics
description: CTF/offline forensics & stego — carve files, inspect metadata, extract hidden data (LSB stego, alternate streams, embedded zips) to get the flag.
---

# Forensics / Steganography (offline artefact)

Use when the target is a disk image / pcap / image / archive / corrupted file whose flag is
hidden in the bytes. The sandbox has binwalk, steghide, exiftool, file, strings, gcc, python.

## Workflow
1. Identify & inspect: `file`, `exiftool` (metadata/comments), `strings` (grep for flag{/HTB{),
   `xxd` head/tail.
2. Carve / extract:
   - binwalk `-e` to pull embedded archives/images.
   - `unzip`/`7z`/`tar` for appended archives.
   - append data after EOF: `tail -c`, `dd`.
3. Stego:
   - LSB in PNG/BMP: script with python (PIL/numpy) to read low bits.
   - steghide/`stegcracker` if a passphrase is implied; exiftool comment.
   - alternate data streams / zip-of-zip.
4. Corrupted/incomplete: `cat`/`binwalk` to find magic bytes, patch/extract manually.
5. If a network capture: parse pcap (scapy/tshark) for interesting streams/creds/traffic.

## Confirmation
- The flag is found by actually extracting bytes (script output). Never fabricate;
  record the file/path + the extraction command as evidence.
