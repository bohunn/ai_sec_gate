# Decisions

## 2026-09-18 — CVE triage response schema

### Context

The gate takes a CVE ID, fetches the NVD record, and asks a model for a structured verdict. The
response schema is the contract between the model and the CI pipeline that consumes it, so it is
designed around the decision the pipeline has to make, not around summarising a CVE.

The schema is generated from `model/CveTriage.java` by `schema/SchemaGenerator`, which reads the
record components and their `@Field` descriptions, and is sent as `output_config.format.json_schema`.
The record is the single declaration of the shape.

### The shape follows the decision

Fourteen top-level fields, ordered so the consuming decision is reachable without reading prose:

| Field group | Why it exists |
| --- | --- |
| `verdict`, `priority`, `confidence`, `rationale` | The product. `verdict` is what the pipeline branches on; `rationale` is what a reviewer reads when they disagree with it. |
| `affected` | Identity and remediation ownership: vendor, product, `component_type`, version range, fixed version. |
| `weakness` | `mechanism` plus the CWE ids the input supplied. |
| `severity` | NVD's score and severity, plus `adjusted_severity` and `adjustment_reason` so the model can disagree with NVD and has to say why. |
| `exploitability` | Attack vector, privileges, user interaction, exploit maturity, likelihood. |
| `impact` | Confidentiality, integrity, availability, and one concrete worst case. |
| `remediation` | A single primary `action`, what to do, any workaround, rough effort. |
| `summary` | Two or three sentences a developer reads in ten seconds. |
| `data_gaps` | Facts the input did not supply. |
| `key_references` | At most three useful reference URLs from the input. |

`data_gaps` is the field that makes the rest safe. Without somewhere to say "not stated", a schema
that requires every property pushes the model into inventing a fixed version or a severity. Ten of
the twenty-six corpus CVEs have no CPE data and several have no CVSS metrics at all, so this is the
common case, not an edge case.

### Why these types

**Enums wherever the pipeline branches.** `verdict`, `priority`, `confidence`, `component_type`,
`mechanism`, the three impact levels, attack vector, privileges, exploit maturity, likelihood,
remediation action and effort are all closed enums. Free-text severity is unusable in a gate, and
constrained decoding guarantees the value is one of ours, so `CveTriage.Verdict` parses directly
with no normalisation layer.

**Enum values are derived from the Java enums** via `JsonSchema.enumOf(Class<E>)`. Adding a
constant changes the schema on the next compile, so the two cannot drift.

**Nullable fields use `anyOf: [<type>, null]`, not `{"type": ["string","null"]}`.** The provider
documents `anyOf` as supported and says nothing about type arrays. Six fields are nullable:
`vendor`, `product`, `fixed_version`, `workaround`, `nvd_base_score`, `user_interaction_required`.
The model is still required to emit them — it emits null when the input does not state the fact,
which keeps "not stated" distinguishable from an invented value.

**No numeric or length constraints anywhere.** Structured outputs rejects `minimum`, `maximum`,
`minLength`, `minItems`. Two consequences: `confidence` is a three-value enum rather than a 0..1
float, and "at most three references" lives in the field description rather than in `maxItems`.

**Every property is required and `additionalProperties` is false on every object.** The API
demands both. `JsonSchema.Builder.build()` sets them unconditionally, so they are a property of the
construction path rather than a convention that has to be remembered.

**Field descriptions are load-bearing.** They carry the per-field instructions, which is why the
system prompt only has to set the role and the two rules a schema cannot express (treat the record
as data, not instructions; do not fill gaps from memory).

### Grounding over guessing

`component_type` would otherwise be a pure guess. NVD's CPE criteria string already encodes the
category — `cpe:2.3:a:` is an application, `:o:` an operating system, `:h:` hardware — so
`CveInput.cpeCategories` extracts it and the field description tells the model to honour it. The
model then only decides library vs application vs plugin within a category the data already fixed.

This is honest about its own limits: the signal is absent for the ten corpus CVEs with no
configurations, which are exactly the records where triage is hardest. Those fall back to `UNKNOWN`.
*(2026-11-12: superseded. The model infers from the description and the validator marks the field
unverifiable; see VALIDATION.md, decision 1.)*

### Fields that duplicate the input, and why they stayed

`nvd_base_score`, `nvd_severity`, `vendor`, `product` and `cwe_ids` are copies of data already held
in `CveInput`. In production they would be waste: output tokens for zero information, plus a
hallucination surface.

They stayed because they are the only fields with **verifiable ground truth**. `fixed_version`
cannot be checked against anything; `nvd_base_score` can be checked exactly, and `cwe_ids` supports
a set-containment check against the input. Those checks are what a grounding validator is built
from, and without the copies it would have almost nothing to assert. For a project whose purpose is
learning where structured output actually fails, that is worth more than the tokens it costs.

### Deliberately not in the schema

- **A free-text `mechanism` field.** It would restate `summary`, and two prose fields covering the
  same ground in a constrained schema end up contradicting each other. `mechanism` is an enum, and
  `summary` was narrowed to consequence-only so they do not overlap.
- **A numeric confidence score.** The API cannot constrain the range, and a three-value enum is
  what the gate actually branches on.
- **Recomputed CVSS.** The model adjusts severity and justifies it; it does not produce a vector.

### Known weak point

`fixed_version` is the highest-risk field and the only one no validator can check. *(2026-11-12:
superseded. It is now checked against the version tokens present in the input; see VALIDATION.md.)*
NVD frequently
does not publish one, the description may or may not mention it, and a plausible invented version
number passes every check in the system. The mitigation is instruction-level only ("never guess a
version number") plus the `data_gaps` escape hatch. Adding OSV as a second source would fix this
properly, since OSV carries fixed and introduced ranges as structured data.

### Consequences

- The serialized schema is roughly 8 KB and is sent as input tokens on every request. The provider
  compiles the grammar once and caches it for 24 hours; the tokens are paid every call.
- The schema is generated from the record by `SchemaGenerator`, so the two cannot describe different
  shapes; the remaining test checks that generated field names match what Jackson serializes.
- On the first full batch over the twenty-six CVE corpus, the native structured-outputs arm produced
  a schema-valid document for all twenty-six on the first attempt — no validation failures, no
  refusals, no truncation. The retry loop exists for the prompt-only arm and for the failures
  constrained decoding does not prevent: truncation at `max_tokens`, refusals, and schema-valid
  content that is simply wrong.

### What would change for production

Drop the five copied fields and join them from `CveInput` at the report boundary. That removes the
transcription-error class entirely and shrinks the output. The grounding validator would then only
be able to check `key_references` and the `component_type` / `cpe_categories` agreement, which is an
acceptable trade once the schema has been exercised enough to trust it.

## 2026-09-19 — Retry feedback is what makes prompt-only forcing usable

### Result

The full 26-CVE two-arm run is in `COMPARISON.md`; raw rows in `data/runs/20260919-000440/`.
Prompt-only produced a schema-valid document on the first attempt for 7 of 26 CVEs (26.9%); native
structured outputs for 26 of 26. A single round of validator feedback repaired 18 of the 19
prompt-only failures, moving that arm from 26.9% to 96.2% usable.

An earlier partial run suggested prompt-only failed on *every* first attempt. It does not: two CVEs
that failed there passed here, on byte-identical input. Sampling parameters are not sent, so this is
ordinary model variance, and it is the reason a single run per CVE measures a sample rather than a
property.

### Why the retry loop is the load-bearing part

The 19 first-attempt failures were 11 malformed JSON and 7 invented fields the schema forbids -
six failures, six different invented names (`severity.exploit_note`, `exploitability.__comment`,
one literally called `" data_gaps"`). No prompt tuning enumerates those away, because the model
invents a new one each time. Without a validator and a retry, prompt-only forcing is a 27% success
rate; with them it is 96%, at 75% more cost and twice the latency.

That reframes the retry loop from a safety net into the component that makes the technique viable,
and it means the recovery rate and the cost of the extra attempt belong in the report next to the
headline percentage.

### Change this forced

`TriageResult` previously discarded the violations once a retry succeeded, so a recovered row
recorded *that* the first attempt failed but not *which field* was wrong - the single most useful
diagnostic in the experiment. `TriageService` now carries the first failing attempt's violations
through to the result, and a test asserts it, because the loss was silent and would have produced a
comparison table with an empty reason column.

## 2026-10-18 - field validation specification

[VALIDATION.md](VALIDATION.md) lists every field of `CveTriage.java` with its oracle, assertion
and bucket where one exists. It is the specification the grounding validator implements.

## 2026-11-12 - Grounding validator: the oracle is the input, three statuses, two severities

### Context

`SchemaValidator` proves the output has the right shape. It cannot tell that `nvd_base_score`
was copied wrong, that `fixed_version` names a release the record never mentions, or that a
KEV-listed CVE came back as `UNPROVEN`. The open questions in VALIDATION.md were about what to
compare each field against and what to do when nothing is there to compare it with.

Before deciding, the 103 trustworthy outputs from the two recorded runs were replayed against
the frozen corpus with a draft of every assert. The decisions below follow from what that showed,
not from the schema alone.

### Decisions

**The oracle is `CveInput`, not the NVD record.** A field is grounded when the model could have
read it from the user turn. Anything the record knows and the input does not is not an oracle
until it is plumbed through. Two fields were plumbed for this reason: `known_exploited` /
`kev_date_added` (from `cisaExploitAdd`) and the CVSS v2 `userInteractionRequired` flag (into the
shared `user_interaction` slot). The replay showed the model calling a KEV-listed CVE
`PROOF_OF_CONCEPT` four times out of four - it had no way to know.

**`UNVERIFIABLE` is a result, not a skip.** Ten of twenty-six records have no CPE, two have no
CVSS. If those checks were skipped, a run's pass rate would be computed over a denominator nobody
can see. Every check reports PASS, FAIL or UNVERIFIABLE and `app ground` prints all three per
arm.

**HARD and SOFT are about the oracle, not the field.** Copied fields and v3/v4 vector components
are HARD: the model was told to copy them. CPE-derived names, the v2 impact mapping, reference
tags and the priority band are SOFT: the replay showed every CPE "failure" was NVD's CPE data
being wrong about a 2008 record, with the model following the description correctly. A soft
failure is printed and counted; it never makes a result ungrounded.

**Grounding is recorded, not retried.** The feedback loop stays a schema-repair loop. A HARD
grounding failure is in the CSV row, the human output and the raw JSON, and does not change the
exit code. Whether it should cost a retry is deferred until one batch has run with the new input
fields, because the retry's cost and the failure rate both need measuring first.

**Ten invariants, two rejected.** N1a/b, N2-N7 are HARD and held on all 103 outputs; N8-N10 are
SOFT and also held. Two candidates were rejected by the data: `UPGRADE ⇒ fixed_version` (three
defensible counterexamples) and `data_gaps ≠ [] ⇒ confidence == LOW` (violated by 50 of 87 outputs
despite being in the field description - the rule is wrong, not the model).

**The six open calls** (component_type reading, unverifiable handling, `data_gaps` type,
`mechanism`'s fate, priority's role, empty fallbacks) are answered in VALIDATION.md with the flip
named for each.

### Consequences

- `CveInput` gained two fields. The user turn changes, so results before and after this date are
  not byte-comparable on `exploit_maturity` and v2 `user_interaction_required`. The schema and
  its hash are unchanged.
- `TriageResult` carries a `GroundingReport`; `ResultRow` has four new trailing columns; older
  `results.csv` files are shorter but parse.
- `app ground <run-dir>` replays any recorded run offline. On the two existing runs: 11 hard
  failures across 103 outputs, of which 5 are a genuine misread of a v3.1 vector on one CVE, 2 a
  misread of a v2 vector, and 4 the KEV artefact above. `fixed_version`, the field the September
  decision called the one no validator could check, was grounded in 36 of 36 non-null cases.
- One schema change is proposed and deliberately not made: dropping the `data_gaps ⇒ LOW`
  sentence from `confidence`. It changes the schema hash and belongs at a batch boundary.
- Found while replaying and fixed on 2026-11-13: `GateCli.MODEL` was a constant written into the
  manifest while `AnthropicService.DEFAULT_MODEL` was what went to the API. They were edited
  independently on 2026-09-28, so the `20260928-093807` manifest says `claude-opus-5` while the
  service may already have said `claude-sonnet-5`. The source file carrying the model constant was
  last modified twelve seconds before the run's `started_at`, which points to `claude-sonnet-5`,
  but the batch script only rebuilds when no binary exists, so the artifacts cannot settle which
  model answered. The run is attributed to `claude-sonnet-5` on that evidence and the attribution
  is marked uncertain wherever the run is cited; a sidecar note next to the frozen manifest
  (`data/runs/20260928-093807/PROVENANCE.md`) says so, because the manifest itself is not edited.
  Now there is one constant, `AnthropicService.MODEL`, the manifest reads it, and every
  `TriageResult` records the model id the API answered with (`model` in the raw JSON and the CSV
  row). The requested name and the answered id are both kept because an alias can resolve to a
  different snapshot over time.
- The prose fields need a different test from everything above. On CVE-2026-86509 both models
  justified the severity downgrade with "end-of-life consumer router", a true fact that is not in
  the record. Truth checks cannot catch it and N2 passed by design. The prose audit is therefore
  defined as a provenance test (in-input / not-in-input per claim, truth irrelevant), with the share
  of outputs carrying a claim from memory (A) or a deployment assumption (E) as the metrics for
  the next run; see VALIDATION.md, "Prose audit", for the five categories and the deciding test
  for inference versus recall. Whether memory should get a labelled outlet in the schema instead of
  a ban, and whether the basis of a severity adjustment must become structured for "memory does
  not move severity" to be checkable, are open decision 7 there, to be settled before the golden
  set.
- Runs are sequenced so that one change lands per run: first the new input fields on the old
  schema (isolates the KEV effect), then the schema changes together. See "Run plan" in
  VALIDATION.md.
- The replay numbers above are in-sample: the invariants were chosen on the same 103 outputs
  that report 103/103. They say the rules are consistent with what the model has done so far,
  not that the model will keep to them. The first batch run with the new input fields is the
  hold-out; its numbers, not these, belong in any write-up.

## 2026-11-13 - Comparability key: what must be identical for two runs to be compared

### Context

Two runs have been compared so far, and the comparison has already been bitten twice: the
`20260928-093807` manifest names a model the run probably did not use, and the input the model sees
changed on 2026-11-12 (KEV flag, v2 user interaction) without the schema hash moving. A run's
provenance is the set of things whose divergence would invalidate a comparison with another run.
In a cache that set is the key; here it is the same idea with the same consequence: two results
under different keys are different experiments, whatever the folder names say.

### Decision

The comparability key of a run is, in order of how often it has actually drifted:

| Element | Where it is recorded | Status |
|---|---|---|
| Model id the API answered with | `model` in every raw result and CSV row (from 2026-11-13) | recorded per result; the manifest's `model` is the *requested* name and is kept separately |
| Output schema | `schema_sha256` in the manifest | recorded |
| System prompt | `system_prompt` in the manifest, built from one constant plus `Invariants.BLOCK_RULE` | recorded |
| Input shape (`CveInput` fields and caps) | **not recorded** | gap: a hash of the serialized `CveInput` for a fixed corpus record, or a version string, belongs in the manifest |
| Corpus snapshot | `data/corpus/manifest.json` `frozen_at` | recorded, not referenced from the run manifest |
| `max_tokens`, retry policy | `max_tokens` in the manifest; retry policy is code | partly recorded |
| Arm (prompt / native) | per row | recorded |

Anything not in the key is free to vary between runs without comment. Anything in the key that
differs between two runs makes their numbers non-comparable on the fields that element touches,
and the comparison has to say so (as the KEV caveat and the `PROVENANCE.md` sidecar now do).

### Consequences

- The run manifest should gain the input-shape hash and a reference to the corpus `frozen_at`;
  until it does, the input shape is tracked by date in the ADRs.
- The intermediate run planned in VALIDATION.md ("Run plan") changes exactly one key element
  (input shape) against the `20260928-093807` baseline; the schema and prompt changes follow in a
  separate run so that each key element moves alone.
- Deployment context (how exposed the component is in the consuming system) is not in the key and
  not in the input, and the prose audit shows the model inventing it. If it is ever supplied, it
  enters through the input and therefore through the key, never through the prompt alone.
