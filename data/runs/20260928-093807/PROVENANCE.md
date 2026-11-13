# Provenance note for run 20260928-093807

`manifest.json` in this directory records `"model": "claude-opus-5"`. For a while that value was in
doubt: it came from a constant in the CLI that was separate from the constant the API client sent,
and the client's constant had been edited to `claude-sonnet-5` twelve seconds before `started_at`.
The batch script only rebuilds the binary when none exists, so the source tree alone could not say
which model answered.

Settled on 2026-11-13 against the API usage record for 2026-09-28: the account shows calls to
`claude-opus-5` only, with 85,293 output tokens, which equals the sum of `output_tokens` in
`results.csv` exactly (input tokens agree within 1%). The run was produced by `claude-opus-5`; the
manifest is correct and the edited constant never reached a running binary.

Lesson kept with the run: the circumstantial evidence (a source edit twelve seconds before the
run) pointed the wrong way, and a weaker signal (the run was 13% slower than the Opus baseline,
where a smaller model would have been faster) pointed the right way. Neither was decisive. What
settled it was a record kept by the other party to the transaction.

From 2026-11-13 the two constants are one (`AnthropicService.MODEL`) and every result records the
model id returned by the API, so this class of doubt cannot recur. Background: DECISIONS.md,
entries dated 2026-11-12 ("Grounding validator") and 2026-11-13 ("Comparability key").
