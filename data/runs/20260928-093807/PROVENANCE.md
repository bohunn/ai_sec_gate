# Provenance note for run 20260928-093807

`manifest.json` in this directory records `"model": "claude-opus-5"`. That value came from a
constant in the CLI that was separate from the constant the API client actually sent. At the time
of this run the client's constant had been changed to `claude-sonnet-5`; the source file carrying
it was last modified twelve seconds before `started_at`. The batch script only rebuilds the binary
when none exists, so the artifacts cannot prove which model answered the 52 calls.

The run is attributed to `claude-sonnet-5` on that evidence, and every citation of it marks the
attribution as uncertain. The manifest is a frozen artifact and is left as written.

From 2026-11-13 the two constants are one (`AnthropicService.MODEL`) and every result records the
model id returned by the API, so this class of ambiguity cannot recur. Background: DECISIONS.md,
entries dated 2026-11-12 ("Grounding validator") and 2026-11-13 ("Comparability key").
