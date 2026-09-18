# Train draft 3ba99ebe

- **Package:** `nits`
- **Kind:** draft — Draft improvement — suggested package change from one or more misses.
- **Title:** Detect redundant secret masking before masked recorder
- **Summary:** Detect redundant secret masking before masked recorder
- **Run:** `slice-1786283196188073000`

_Applied by `doomer train results apply`. Synthetic draft — do not bank summary into `agent/voice.md`._

## What we want to improve

Detect calls that apply secret-masking to a message when the same message is deterministically sanitized later by a recorder or issue-logger in the same call path, because the earlier masking is redundant and noisy.

## Why this matters

Maintainers care because redundant masking obscures which component enforces redaction and adds noisy, review-time churn; this is a non-blocking stylistic nit rather than a correctness defect. Masking is still valid when it protects a different channel or enforces a distinct policy, so detection should only target truly redundant in-path masking.

## Examples

- An HTTP API handler strips user tokens from an error string then calls the request recorder which also strips tokens before storing diagnostics, so the initial scrub is redundant.
- A command-line tool masks credentials before sending an error report into the project issue service which guarantees sanitization on ingest, producing duplicate masking operations.
- A background job masks sensitive fields prior to calling a persistence API that enforces masking on write, creating repeated operations that clutter diffs.

## Keep it focused

- Masking applied because the message is sent directly over a protocol socket to a client, bypassing the recorder, so the upstream call is necessary.
- Both upstream and downstream maskers intentionally coexist because they implement different redaction policies or cover distinct threat surfaces, so neither is redundant.

## Done when

- [ ] Flags when code calls a secret-masking function on text that is then forwarded into a recorder or issue-logger that deterministically masks the same content before persisting or emitting.
- [ ] Does not flag when masking protects a different output channel that bypasses the recorder, such as a direct protocol payload to a client.
- [ ] Emits a concise nit comment naming the downstream sanitizer or recorder guarantee that makes the earlier masking redundant.
- [ ] Does not flag unrelated transformations like encoding or escaping that must remain even if the recorder also masks secrets.
