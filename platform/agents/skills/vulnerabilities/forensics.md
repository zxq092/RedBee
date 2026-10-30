---
name: forensics
description: CTF/offline forensics & stego — carve files, inspect metadata, extract hidden data; pcap attack-traffic reconstruction and MFT/NTFS last-mile included.
---

# Forensics / Steganography (offline artefact)

Use when the target is a disk image / pcap / image / archive / corrupted file whose flag is
hidden in the bytes. The sandbox has binwalk, steghide, exiftool, file, strings, gcc, python,
tshark, analyzeMFT.

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
5. If a network capture: see pcap playbook below.

## pcap attack-traffic reconstruction (fixed playbook)

When the pcap contains an ATTACK SESSION (command injection / reverse shell / exfiltration)
and the flag is in the traffic:

1. Inventory: `tshark -r cap.pcap -q -z conv,tcp` (top conversations) and
   `tshark -r cap.pcap -Y http -T fields -e http.request.full_uri` (HTTP overview).
2. Dump every conversation to files:
   `tshark -r cap.pcap -q -z follow,tcp,ascii,<stream_id>` per stream (iterate stream ids
   from the conv list). Save each to its own file in the workdir.
3. In each stream, separate command/response pairs (attacker lines vs output lines).
   Grep the OUTPUT side for: base64 blobs, repeated fixed-width tokens, hex strings,
   anything that looks chunked (`[a-z0-9+/=]{8,}` runs).
4. Exfil reassembly: if a token appears N times in ascending contexts, it's likely the flag
   sent in pieces or repeated probes — extract all occurrences in order, dedupe preserving
   order, then join/decode (base64/hex/rot). Try both raw and reversed order.
5. Obfuscated commands on the input side (base64/eval/unescape chains): decode the chain
   step by step in python; the final stage often reveals how the flag was encoded — mirror
   that decode on the output side.
6. Verify: the recovered string matches the flag pattern before submitting.

## MFT / NTFS last mile (hidden records)

When analyzing an MFT dump ($MFT file) with hidden/deleted entries:

1. Parse with analyzeMFT python API (no CLI):
   `from analyzeMFT import MftAnalyzer; a = MftAnalyzer(in, out); await a.analyze()`
   (asyncio API). Or script your own MFT record walker: record size 1024B,
   fixup array applied first, then attributes walked as TLV.
2. Filter entries with unusual SiFlags (e.g. 0x06 hidden+system) or entries whose filename
   matches the challenge theme.
3. For each interesting record, dump ALL attributes — the flag is often in a resident DATA
   attribute (content inline in the MFT record, no cluster allocated) or split across
   multiple resident attributes. Read attribute body bytes directly:
   resident data lives at record_offset + attr_header_offset + value_offset, length
   value_length.
4. If content is split across records: collect from every matching record in FILE REFERENCE
   ORDER (record number), not filename alphabetical; join; then decode.
5. Verify against the flag pattern; submit the join script + output as evidence.

## Confirmation
- The flag is found by actually extracting bytes (script output). Never fabricate;
  record the file/path + the extraction command as evidence.
