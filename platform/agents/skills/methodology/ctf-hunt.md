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
