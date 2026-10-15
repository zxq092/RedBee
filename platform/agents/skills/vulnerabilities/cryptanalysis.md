---
name: cryptanalysis
description: CTF/offline crypto analysis — identify the cipher, script the solve with python/z3/sympy in the sandbox, get the flag.
---

# Cryptanalysis (offline artefact)

Use when the target is ciphertext / a crypto challenge file (or a service doing crypto),
not a web endpoint. The model has the mathematical reasoning; the sandbox provides python,
z3-solver, sympy, pycryptodome to script the solve. Payloads/scripts run in the sandbox via
python/bash tools, not as prose.

## Workflow
1. Recon the artefact: `file`, `xxd`/`strings` on the file; identify the cipher/format
   (AES/RC4/RSA/ECC/chaCha, or a custom scheme). Look for a key/nonce/round numbers in comments/names.
2. Classify:
   - **Stream/block ECB/CBC**: is IV reused? is key weak/short? script known-plaintext / padding oracle.
   - **AES-ECB**: detect duplicate 16B blocks → no IV / ECB leak.
   - **RSA**: small e / small n / common factor between moduli / weak primes → factor with sympy or z3.
   - **LFSR/LCG**: recover state from output (z3).
   - **Custom/encoding**: base64/hex/byteswap first, then the actual cipher.
3. Script the solve with python (`Crypto.Cipher`, `z3.Solver`, `sympy`), run it in the sandbox,
   print the flag / plaintext.
4. Confirm: flag matches the expected flag-pattern; submit a finding with the solve script +
   recovered flag as evidence.

## Confirmation
- The flag is obtained by actually running the solve script and capturing its output —
  never fabricate. If you can't solve in reasonable attempts, say so.
