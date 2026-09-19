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
| Median latency per CVE | 26.3 s | 12.6 s |

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
`exploitability.__comment`, and one literally named `" data_gaps"` with a leading space. **Six
failures, six different invented names.** The model reaches for somewhere to editorialise and
invents a plausible key each time, so no amount of prompt tuning enumerates them away. This is
exactly what `additionalProperties: false` exists to catch, and constrained decoding makes it
structurally impossible.

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
