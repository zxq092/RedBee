---
name: cryptanalysis
description: CTF/offline crypto analysis — identify the cipher, script the solve with python/z3/sympy in the sandbox, get the flag. LCG/PRNG recovery, AES advanced attacks included.
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
   - **Custom/encoding**: base64/hex/byteswap first, then the actual cipher.
3. Script the solve with python (`Crypto.Cipher`, `z3.Solver`, `sympy`), run it in the sandbox,
   print the flag / plaintext.
4. Confirm: flag matches the expected flag-pattern; submit a finding with the solve script +
   recovered flag as evidence.

## LCG / PRNG state recovery (very common in CTF)

Given consecutive outputs `s_{i+1} = (a*s_i + c) mod n` (parameters a/c/n may be unknown):

- **All parameters known, want next values**: just iterate forward.
- **a, n known, c unknown**: `c = s1 - a*s0 mod n`.
- **n unknown**: `n | gcd(s1-s0, s2-s1, s3-s2, ...)` — collect several differences, take gcd,
  usually equals n or a small multiple.
- **a unknown, n known**: `a = (s2-s1) * inverse(s1-s0, n) mod n`.
- **Truncated outputs** (only top k bits of each s_i visible, e.g. `s_i >> 16`):
  model each unknown low part as a z3 BitVec, constrain `s_{i+1} == (a*s_i+c) mod n`
  for 6-10 consecutive outputs, `z3.Solver().check()` → recover full states. This is the
  standard "truncated LCG" solve — needs more samples than parameters.
- **z3 template skeleton**: `s = [z3.BitVec(f's{i}', 64) for i in range(k)]`;
  add one equation per pair; constrain the visible part `z3.LShR(s[i], shift) == observed[i]`.
- **Mersenne Twister (random module)**: 624 consecutive 32-bit outputs untemper → clone state
  (`random.setstate`) → predict future values. Untemper is a fixed bit-twiddle inverse, script it.
- **random.seed() with small/known seed space**: brute-force the seed, compare first outputs.

## AES advanced (when the round structure is broken)

- **Shuffled round keys / round order permuted**: build an encryption oracle from the given
  code (encrypt is usually a pure function of (block, round_keys_in_order)). If you control
  plaintext (chosen-plaintext): encrypt a few single-bit-difference blocks, compare which
  round key causes the first divergence — this localizes round order. Then permute the key
  schedule hypothesis and verify against a known plaintext/ciphertext pair. Frame it as a
  permutation-search problem (n small, e.g. 10 rounds); verify candidates against the given
  test vector before decrypting the target.
- **AES-CTR with reused nonce/counter**: XOR of two ciphertexts = XOR of plaintexts;
  crib-drag with known file formats/headers.
- **Weak key from PRNG**: if the key came from a predictable PRNG (see above), recover the
  PRNG state instead of brute-forcing the key.

## Confirmation
- The flag is obtained by actually running the solve script and capturing its output —
  never fabricate. If you can't solve in reasonable attempts, say so.
