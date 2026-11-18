# Prompt-only vs native structured outputs

26 CVEs, 2 arms, 1 run each, 52 calls. Model `claude-opus-5`, identical system prompt and schema
across arms; the only variable is how JSON is forced. Both arms read the same frozen NVD records
from `data/corpus/`, so the inputs are byte-identical. Raw data: `data/runs/20260919-000440/`.

## Headline

| | prompt-only | native structured outputs |
| --- | --- | --- |
| **Schema-valid on first attempt** | **7/26 (26.9%)** | **26/26 (100%)** |
| Usable after retries | 25/26 (96.2%) | 26/26 (100%) |
| Total attempts for 26 CVEs | 43 | 26 |
| Input tokens | 197,103 | 135,424 |
| Output tokens | 53,435 | 25,547 |
| Cost at Opus 5 rates | $2.32 | $1.32 |
| Median latency per CVE | 26.4 s | 12.6 s |

Native structured outputs never failed validation, which is what constrained decoding guarantees
by construction. The result worth reporting is not that it won but by how much, and what the
prompt-only failures actually were.

## First-attempt validity by stratum

| Stratum | prompt | native |
| --- | --- | --- |
| control | 2/4 | 4/4 |
| sparse | 1/4 | 4/4 |
| reject | 0/2 | 2/2 |
| disputed | 0/2 | 2/2 |
| metrics | 1/4 | 4/4 |
| scale | 1/3 | 3/3 |
| cwe | 0/2 | 2/2 |
| adversarial | 1/3 | 3/3 |
| stability | 1/2 | 2/2 |

Prompt-only failure is spread across every stratum rather than concentrated in the thin records.
Even the four `control` CVEs — fully scored, clearly described — failed half the time.

## Why prompt-only failed

| Failure | Count |
| --- | --- |
| Response was not valid JSON | 11 |
| Invented a field the schema forbids | 7 |

The invented fields were `severity.exploit_note`, `severity.exploit_maturity_note`,
`severity.attack_vector_note`, `exploitability.exploit_maturity_note`,
`exploitability.__comment`, and one literally named `" data_gaps"` with a leading space. **Seven
failures, six different invented names.** The model reaches for somewhere to editorialise and
invents a plausible key each time, so no amount of prompt tuning enumerates them away. This is
exactly what `additionalProperties: false` exists to catch, and constrained decoding makes it
structurally impossible. (The third run below softens "each time": 4 of its 9 invented names had
appeared before, 5 had not. A denylist in the prompt would have caught some and missed the rest.)

The 11 parse failures are after fence-stripping and preamble-trimming, so they are genuine
malformed JSON, not markdown wrapping.

## Retries are what make prompt-only usable, not the prompt

18 of the 19 prompt-only first-attempt failures were repaired by a single round of validator
feedback. That moves the arm from 26.9% to 96.2% usable — the retry loop, not the instruction, is
what carries the technique.

The cost of that is visible: 43 attempts against 26, and **75% more cost and 2x the latency**.
Per attempt the two arms are comparable — prompt-only averages 4,584 input and 1,243 output
tokens, native 5,208 and 982 — so the entire difference is re-asking, not a fatter payload. Native
actually sends slightly *more* input per call, because the schema travels in `output_config`
either way.

## Non-determinism

An earlier, discarded run of the same corpus gave `CVE-2026-20963` and `CVE-2026-24061` as
first-attempt failures; in this run both passed. Same frozen bytes, same prompt, same arm,
opposite result. Sampling parameters are not sent (Opus 5 rejects them), so this is ordinary model
variance.

One run per CVE therefore measures a sample, not a property. The 26.9% figure should be read with
that caveat, and repeating at `RUNS=3` is what would put an error bar on it.

## Content agreement

The two arms reached the same verdict on 24 of 26 CVEs. One differed — `CVE-2024-12366`, a
CRITICAL with no CWE and no CPE, where prompt-only said `NEEDS_HUMAN_REVIEW` and native said
`WARN`. One prompt-only call failed with an API error and produced no verdict.

Constraining the grammar did not measurably degrade the judgement, which is the concern that
motivated checking content at all.

The near-duplicate pair `CVE-2024-36422` / `CVE-2024-36423` — the same Flowise XSS reported twice —
drew `WARN` from both arms on both CVEs, so neither technique showed instability on the one probe
designed to detect it.

## Conclusion

Native structured outputs wins on every axis measured: validity, cost, latency, and operational
simplicity. Prompt-only is not unusable, but it is only usable *because* a validator and a retry
loop stand behind it, and that scaffolding costs 75% more per triage.

The finding that generalises beyond this comparison: prompt-only failures were **invented fields**
and **malformed JSON**, not wrong values. Both are failures constrained decoding eliminates
outright. Neither is a failure that grounding or semantic validation would catch — and conversely,
nothing in this experiment tests whether either arm gets the facts right. Schema validity and
truthfulness are separate problems.

## Third run, new input shape (20261117-233510)

Same model, schema and prompt; the input gained `known_exploited`, `kev_date_added` and the v2
user-interaction flag (VALIDATION.md, "Run 20261117-233510").

| | prompt-only | native |
| --- | --- | --- |
| Schema-valid on first attempt | 8/26 | 25/26 |
| Usable after retries | 26/26 | 26/26 |
| Total attempts | 44 | 27 |
| Cost at Opus 5 rates | $2.37 | $1.47 |
| Median latency per CVE | 25.4 s | 14.0 s |

The native miss is not a constrained-decoding failure: `CVE-2026-76960` hit the 4,096 `max_tokens`
ceiling and was repaired by the truncation retry with no schema violation. Prompt-only failed 9
times on malformed JSON and 9 times on an invented field. Verdicts agreed on 25 of 26, the one
disagreement being `CVE-2024-12366` again, and every verdict in both arms equals the verdict of the
same arm in both earlier runs.

## Does constrained decoding invite filling from memory? (adjudicated 2026-11-17)

Hypothesis (2026-11-13): constrained decoding forces every field to be filled, and a field that must
be filled may be filled from memory. The automatic pre-screen could not decide it: native had more
flagged outputs than prompt in the first run (18 of 26 vs 14 of 25) and the same in the second
(14 vs 13), inside the run-to-run noise.

Adjudication of every flagged line into provenance categories (VALIDATION.md, "Prose audit")
removes the noise lines and keeps the gap in both runs:

| outputs with ≥1 memory claim (A) | native | prompt |
| --- | --- | --- |
| run 20260919-000440 | 9/26 | 5/25 |
| run 20260928-093807 | 8/26 | 4/26 |
| run 20261117-233510 (new input shape, adjudicated blind to arm) | 7/26 | 4/26 |

The same arm moves by one output between the two identical runs; the arms differ by 4, 4 and 3.
Two CVEs carry memory claims in the native arm only in all three runs. The gap holds on the
mechanical pre-screen lines alone, without the lines the adjudicator added (8 vs 4, 6 vs 3, 5 vs 3).
Deployment assumptions (E) lean the same way with less weight: native 4, 5, 6 against prompt
4, 3, 2.

This is the one cost of native structured outputs found in this experiment; every axis above
favours them. Three runs, two input shapes, one direction: it is read as a property of the
technique on this task, not of one corpus run. What the data does not separate is the mechanism,
a field that must be filled or a model that simply writes more prose when it is not spending effort
on formatting; the native arm has more flagged lines in every run. The first adjudication was not
blind to arm, the third was. Native prose has to be audited for provenance; prompt-only prose has
to be audited too, less often.
