---
name: ctf-hunt
description: Objective-hunting methodology for CTF / flag-capture targets (as opposed to OWASP class fan-out). The hunter's default question is "what data here is special / what should not be shown to me", not "which vulnerability class exists". Covers: reading the DATA itself (tables, list rows, response bodies) before structure (JS/params/status codes); the anomaly signal catalog (special naming like a ticker literally called FLAG, template/filler divergence, encoded strings, 302 to unfamiliar paths, other users' data, hidden DOM fields via data-* attributes and HTML comments, list-vs-URL-space mismatch); breadcrumb chasing (tokens, links, data-* attributes, indirect references such as list/detail split and auth gates); batch sweep discipline for large object spaces (one bash loop, 200~1000 per batch, grep the objective pattern; hand-trying IDs one by one is sampling, not searching); and stop-on-hit (submit the full raw response as evidence immediately, then end). Calibrated on the xben-002 platform (indirect IDOR variant, 2026-09-30). Use when the task objective is a single target object (flag/shell/specific record) rather than broad vulnerability coverage.
sources: operator_experience
---

# CTF / Objective Hunt Methodology

You are hunting ONE specific object (a flag, a shell, one record), not a
list of vulnerability classes. Class fan-out (sqli child + xss child + auth
child) is the WRONG shape for this task: each class specialist asks a
different question, and the answer to your question ("which data is
special?") is not in their question set.

## ⚠️ IRON RULE — Submit the flag IMMEDIATELY

The moment you see a flag-like string (`HTB{...}`, `SEKAI{...}`, `gctf{...}`,
`hkcert22{...}`, `flag{...}`, `FLAG{...}`) in ANY output — HTTP response, file
content, command output, decoded data — call `submit_finding` RIGHT NOW with:

- title: `[CTF] flag found in <location>`
- evidence: the full flag string
- poc: what you did to extract it
- severity: high, vuln_class: ctf_flag

**Do NOT wait to "confirm" it. Do NOT explore more paths first. Submit now,
then verify.** Budget is finite; an unsubmitted flag = zero points.

## ⛔ ZERO-FABRICATION — the flag must be COPIED, never constructed

- The flag must appear **byte-for-byte in your actual tool output** (HTTP response,
  file content, command stdout, decoded register bytes). Copy it.
- **NEVER** invent, reconstruct, "plausibly complete", or guesser-fill a flag —
  not from a partial pattern, not from the target's theme, not from "what a flag
  probably looks like". A decoded buffer that reads `SIM-PLC-202K...` is NOT a flag;
  do not turn register values you did not actually read into `FLAG{...}`.
- Before submitting, grep your last tool outputs for the exact string. If you cannot
  point at the output line containing it verbatim, you do NOT have the flag — say so
  honestly in your final report (what you read, where you expected the flag, next step).
- The engine rejects submissions whose flag never appeared verbatim in tool output.

## The default question

For every page, dataset, or response you fetch, ask FIRST:

> "What data here is special? What data should NOT be shown to me?"

The objective (flag) is usually hiding as **anomalous data**, not as an
injection point. Anomaly-driven reading is the primary discipline;
vulnerability-class reasoning is secondary and only when it IS the
breadcrumb.

## Step 1 — Read the data itself, not the structure

Fetch a page and read the **data**: tables, list rows, response bodies,
comment blocks. Only afterwards look at structure (JS, params, status
codes). A class specialist reading an orders page extracts `<script>` and
form params; the hunter extracts the **rows**.

- Enumerate every row/entry in every list you find.
- Note the template: most rows share a pattern (e.g. lorem ipsum filler,
  a common ticker, sequential dates). The row that breaks the pattern is
  the lead.

## Step 2 — The anomaly signal catalog

Dig in immediately on any of these (do not wait for "better tooling"):

1. **Special naming** — an entry whose name/ticker/label is literally the
   objective keyword or theme word (e.g. a trade row whose ticker is
   `FLAG`).
2. **Template divergence** — content that differs from the filler/template
   used by sibling rows (different length, different language, real data
   where others are lorem ipsum).
3. **Encoded strings** — base64 / hex / rot / URL-encoding in a place that
   otherwise holds plain text.
4. **302/redirect to an unfamiliar path** — a link or response that points
   outside the known page set.
5. **Other users' data** — any confirmed cross-user read (IDOR) is a
   secondary exploit surface: sweep what the access leaks.
6. **Hidden DOM fields** — `data-*` attributes, HTML comments, disabled
   inputs, `href="#"` links driven by JS (`data-order-id`, `data-token`,
   `data-ref`).
7. **List-vs-URL-space mismatch** — the listing page shows N entries but
   direct URL access works for IDs outside the list (or the list omits
   entries that exist).

## Step 3 — Breadcrumb chasing

Follow every new token / link / `data-*` attribute / endpoint to the end.
The common hiding pattern is **indirect reference**:

- list page (public) shows the entry, detail/receipt (auth-gated) holds
  the payload;
- a DOM attribute carries the real object ID while `href="#"`;
- an archive endpoint mirrors a "live" endpoint for older/special objects.

One breadcrumb at a time, but do not stop until the chain terminates.

## Step 4 — Batch sweep (large object spaces ONLY)

When no listing page exposes the full set and the object space is large
(hundreds to thousands of numeric IDs / tokens / paths):

- Write **ONE bash loop** that sweeps the space systematically
  (200~1000 per batch; continue in chunks), grepping each response for the
  objective pattern (flag template, or "differs from filler").
- Persist the raw responses so you can re-grep without re-fetching.
- Hand-trying IDs one by one is **sampling, not searching** — three manual
  fetches in an 800-ID space is how 90 minutes get burned.
- Exception: if a listing page already exposes the full set (e.g. 5 rows),
  fetching all of it in one command IS the systematic sweep — no loop
  needed. Match the tool to the space.

## Step 5 — Stop on hit

The moment the objective is in hand:

1. `submit_finding` with **evidence = the full raw response** (the exact
   body containing the flag/object, unedited) and a title naming the path
   (endpoint + object ID) and the access-control defect that exposed it.
2. `record_coverage` for the surface.
3. Print `done`. The task ends when the objective is recorded — do not
   keep "over-verifying" after a clean hit.

## Anti-patterns (observed failures)

- **Class-locked drift**: spending 20+ turns testing SQLi/XSS on a target
  whose objective is a leaked record. Only touch a vulnerability class
  when it is the breadcrumb to the objective.
- **Recon bloat**: 30+ minutes of nmap/port/fingerprint work on a target
  whose profile already carries the login chain and endpoint map. If the
  brief says RECON ALREADY DONE, probe directly.
- **Structure-only reading**: fetching the page but only parsing
  `<script>`/headers, never the `<table>` body.
- **Sampling**: 3 hand-picked IDs in a large space with no loop.
- **Premature stop on side findings**: a default-credential disclosure or
  an IDOR confirmation is a *lead*, not the objective — record it and keep
  hunting until the objective itself is captured.

## Crypto Service / Artifact — Concrete Solve Templates

When the challenge involves cryptography, script the break in the sandbox
(python + z3 + sympy + pycryptodome available). Do NOT try to solve by hand.

### LCG (Linear Congruential Generator)
```python
# Given outputs s0,s1,... from s_{n+1} = (a*s_n + c) mod m
# Recover a,c,m then predict next outputs
from sympy import *
outputs = [/* observed values */]
# m from GCD of differences
diffs = [outputs[i+1]-outputs[i] for i in range(len(outputs)-1)]
m = abs(diffs[0])
for d in diffs[1:]:
    m = gcd(m, abs(d))
# a from consecutive
a = (outputs[2]-outputs[1]) * pow(outputs[1]-outputs[0], -1, m) % m
c = (outputs[1] - a*outputs[0]) % m
# predict next
next_val = (a*outputs[-1] + c) % m
```

### LFSR (Linear Feedback Shift Register)
```python
# Given output bits, recover feedback polynomial via z3
from z3 import *
bits = [/* observed bits */]
n = len(bits)
# try common tap positions
for taps in [16, [1,0,3], [1,1,0,3]]:
    s = Solver()
    state = [Bool(f's{i}') for i in range(n+16)]
    for i in range(n):
        s.add(state[i] == bits[i])
    # feedback: new = XOR of taps
    # ... solve for unknown bits
    if s.check() == sat:
        m = s.model()
        # extract state, predict next bits
```

### RSA — Common Attacks
```python
from sympy import *
# Small e, large m: m^e < n → integer e-th root
e, n = 3, 123456789  # example
ct = 12345678901234567890
# check if perfect power
root = integer_nthroot(ct, e)
if root[1]: plaintext = root[0]
# Wiener attack (small d): continued fractions
# Common factor between moduli: gcd(n1, n2)
# Small primes: factor with sympy
```

### AES-ECB — Duplicate Block Detection
```python
import base64
data = base64.b64decode(ciphertext_b64)
blocks = [data[i:i+16] for i in range(0, len(data), 16)]
from collections import Counter
dupes = [(b,c) for b,c in Counter(blocks).items() if c > 1]
# duplicate blocks = ECB mode leak → known-plaintext or block reorder
```

### XOR / Encoding
```python
# Single-byte XOR: brute force all 256 keys
for key in range(256):
    decoded = bytes(b ^ key for b in data)
    if b'flag' in decoded.lower() or b'HTB' in decoded:
        print(f"key={key}: {decoded}")
# Multi-byte XOR: use known plaintext ("flag{" etc.)
```

### Interactive Crypto Service Protocol
```
1. Connect: echo "input" | nc host port
2. Read the full banner/protocol description
3. If it asks for a number/choice: send it
4. If it gives ciphertext: script the decrypt
5. If it's a maze/puzzle: read the source or reverse the logic
6. Submit the flag immediately when found
```

### Priority Order for Crypto Challenges
1. Read the source code if available (often reveals the exact weakness)
2. Check for hardcoded keys/IVs/flags in source
3. Identify the scheme → apply the matching template above
4. Script with z3/sympy/pycryptodome
5. **Submit flag immediately**

### Deep Playbooks — load_skill when the shape matches
- LCG / truncated LCG / MT19937 / predictable PRNG, or shuffled-round AES:
  `load_skill('cryptanalysis')` — has the full state-recovery z3 templates.
- pcap with an attack session (command injection / exfil) or an MFT/$MFT dump:
  `load_skill('forensics')` — has the fixed tshark follow-stream + MFT resident-DATA playbooks.
- JWT/JWKS forgery (eyJ tokens): `load_skill('hunt-jwt-crypto')`.
- **Industrial / OT target** (port 502 Modbus, 102 S7comm, 20000 DNP3, 4840 OPC-UA,
  47808 BACnet, or words PLC/HMI/SCADA/RTU/historian):
  `load_skill('ot-ics-security')` — register maps, unit-id sweep, safe read-only probes.
- **Router / routing target** (port 179 BGP, 89 OSPF, 161 SNMP, 520/521 RIP, or the
  challenge mentions a router / prefix / AS / route leak):
  `load_skill('routing-protocols')` + `load_skill('network-infrastructure')`.

### Tool surface (do not waste turns)
`bash`, `read`, `write`, `edit`, `grep`, `find`, `ls` run **on the host**.
`terminal`, `exec_command`, `python` run **inside the Kali sandbox**, which is where
`pymodbus`, `scapy`, `snmpwalk`, `tcpdump`, `frr/vtysh`, `impacket` and friends live.
If an import or binary is missing, switch tools — do not retry the same interpreter.
