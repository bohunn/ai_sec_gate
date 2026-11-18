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
  service had just been edited to say `claude-sonnet-5`. The source tree could not settle it (the
  batch script only rebuilds when no binary exists); the API usage record for that day did: only
  `claude-opus-5` was called, and its output-token total equals the run's `results.csv` sum exactly.
  The manifest was right and the edit never reached a running binary. The sidecar
  `data/runs/20260928-093807/PROVENANCE.md` records the doubt and its resolution, because the
  manifest itself is never edited. Now there is one constant, `AnthropicService.MODEL`, the manifest reads it, and every
  `TriageResult` records the model id the API answered with (`model` in the raw JSON and the CSV
  row). The requested name and the answered id are both kept because an alias can resolve to a
  different snapshot over time.
- The prose fields need a different test from everything above. On CVE-2026-86509 both runs
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
`20260928-093807` manifest's model name could not be trusted from the source tree alone and had
to be confirmed against the API usage record, and the input the model sees changed on 2026-11-12
(KEV flag, v2 user interaction) without the schema hash moving. A run's
provenance is the set of things whose divergence would invalidate a comparison with another run.
In a cache that set is the key; here it is the same idea with the same consequence: two results
under different keys are different experiments, whatever the folder names say.

### Decision

The comparability key of a run is, in order of how often it has actually drifted:

| Element | Where it is recorded | Status |
|---|---|---|
| Model id the API answered with | `model` in every raw result and CSV row (from 2026-11-13) | recorded per result; the manifest's `model` is the *requested* name and is kept separately |
| Output schema | `schema_sha256` in the manifest; pinned by a test (`81f1521f6e417e68` for the three recorded runs, `b6fac04f10752357` from 2026-11-18) | recorded, deterministic by construction |
| System prompt | `system_prompt` in the manifest, built from one constant plus `Invariants.BLOCK_RULE` | recorded |
| Input shape (`CveInput` fields and caps) | `input_shape_sha256` in the manifest (from 2026-11-13): hash of a fully populated `CveInput` sample plus the caps; pinned to `bc30ad24d93e88a4` by a test | recorded; see the next entry for the day it was not deterministic |
| Corpus snapshot | `data/corpus/manifest.json` `frozen_at`, copied into the run manifest as `corpus_frozen_at` (from 2026-11-13) | recorded |
| `max_tokens`, retry policy | `max_tokens` in the manifest; retry policy is code | partly recorded |
| Arm (prompt / native) | per row | recorded |

Anything not in the key is free to vary between runs without comment. Anything in the key that
differs between two runs makes their numbers non-comparable on the fields that element touches,
and the comparison has to say so (as the KEV caveat and the `PROVENANCE.md` sidecar now do).

### Consequences

- The run manifest carries the input-shape hash and the corpus `frozen_at` from 2026-11-13. The
  two recorded runs predate both fields; their input shape is the one before the KEV and v2
  user-interaction fields were added.
- The intermediate run planned in VALIDATION.md ("Run plan") changes exactly one key element
  (input shape) against the `20260928-093807` baseline; the schema and prompt changes follow in a
  separate run so that each key element moves alone.
- Extending the corpus does not break comparability on the records already in it, provided those
  records stay byte-identical. `freeze` never re-fetches a record that is on disk, keeps
  `frozen_at` as the date of the first freeze, adds `last_extended_at` when new records arrive, and
  writes each record's SHA-256 into the corpus manifest so "byte-identical" is checkable rather
  than assumed. Re-freezing an existing record is a key change; adding a hold-out is not.
- Two runs under an identical key (`20260919-000440`, `20260928-093807`) are the project's only
  measurement of run-to-run variance; the spread between them per metric is the noise floor for
  every later comparison (VALIDATION.md, "Noise floor").
- Deployment context (how exposed the component is in the consuming system) is not in the key and
  not in the input, and the prose audit shows the model inventing it. If it is ever supplied, it
  enters through the input and therefore through the key, never through the prompt alone.

## 2026-11-13 - The input-shape hash was non-deterministic for one day

### What happened

`input_shape_sha256` was added to the run manifest on 2026-11-13 as the input-shape element of
the comparability key. Its value differed between two consecutive invocations of `app manifest`
with no code change in between: `bb84c1313802b936`, then `bc30ad24d93e88a4`. The cause was a
`Map.of` holding the three input caps: immutable maps iterate in an order randomized per JVM
process, so the serialized sample, and its hash, changed from process to process. A unit test that
serialized the shape twice in one process passed, because within one JVM the order is stable.

No run used the value. It existed for a day in the working tree and in no manifest under
`data/runs/`.

### Why it matters more than a bug

A missing hash is a visible gap. A random hash is false precision: two runs with the same input
shape would have shown different hashes, and a reader would have concluded the shape had changed
and explained a difference with an artifact that measured nothing. The same failure class as a
single model run read as a property: one observation of a non-deterministic process looks like a
value and is a sample.

### What changed

- Insertion-ordered maps in `CveInput.shape()` and in the corpus manifest; `Map.of` is not used
  on anything that is hashed or written as provenance.
- Both key hashes are pinned to constants by tests (`theInputShapeHashIsPinned`,
  `theSchemaHashIsPinned`). A pinned test does two jobs: it fails on the first CI run on another
  JVM if serialization is not deterministic, and it fails on any later change of shape, forcing the
  constant and a dated entry here to be updated together. The schema hash was already stable
  across the two recorded runs; the pin turns "stable twice" into a property checked on every
  build, and the stability has a construction behind it (insertion-ordered property map, fixed
  property order on the schema record, record components and enum constants in declaration order).
- Measured, not assumed: the serialized user turn for one corpus record (`app input CVE-2024-28088`)
  hashes identically across three processes (`47a5beeaad2b5240`), so "the inputs are byte-identical"
  in COMPARISON.md is a measurement. Record serialization follows component order and every
  collection in `CveInput` is insertion-ordered.
- Rule carried forward: `RUNS >= 3` applies to the pipeline's own determinism, not only to the
  model. Anything written as provenance is checked across independent processes before it is
  trusted.

## 2026-11-17 - The prose audit is adjudicated; the memory gap by arm stands

### What happened

The 136 pre-screen lines in `data/prose_audit/candidates-20261113.md` were categorised by hand
into A memory / B paraphrase / C generic / D inference / E deployment assumption, 27 lines the
pre-screen had missed were added, and `scripts/prose-audit-table.py` reads the file. Outputs with
at least one memory claim: native 9/26 and 8/26, prompt 5/25 and 4/26. Outputs with at least one
deployment assumption: 4, 5, 4, 3. Full table and reading in VALIDATION.md, "Prose audit".

### What it decides

- The hypothesis recorded in COMPARISON.md on 2026-11-13 (constrained decoding invites filling from
  memory) moves from "under doubt" to "stands with caveats": the arm gap is 4 outputs in both runs
  against a between-run spread of 1, and it holds on the arm-blind pre-screen lines alone. It is
  still a two-sample floor and the adjudicator saw the arm label; the next batch is the third point.
- Deployment assumptions are not an arm effect. They appear in about one output in six either way
  and only in `adjustment_reason` and `rationale`, the two fields next to the verdict. That is an
  input problem (deployment context is not in the input, see the comparability-key entry), not a
  JSON-forcing problem.
- Decision 7 gets its data: `adjustment_reason` has 28 A or E lines out of 39 flagged, the worst
  ratio of any field, and it is what N8 reads through `adjusted_severity`. Whether the answer is a
  labelled memory outlet or a structured `adjustment_basis` is still open; it is no longer open
  whether the field needs one.

### Rules carried forward

- Adjudicated letters live in the candidates file next to the pre-screen line, with a note in
  parentheses for anything disputed or added; the script counts disputed and added lines separately
  so a result can be checked against them. Generated worksheets (`worksheet-*.md`) carry raw model
  outputs and are not committed.
- The arm label in the section header makes blind adjudication impossible in this layout. The next
  adjudication either strips the header to an opaque id or keeps relying on the pre-screen-only
  control; stripping is better and costs one mapping file.

## 2026-11-18 - First run on the new input shape; what it settled and what it exposed

### What happened

Run `20261117-233510`: `claude-opus-5`, unchanged schema and prompt, input with `known_exploited`,
`kev_date_added` and the v2 user-interaction flag. One key element moved. Replay and comparison
with the baseline pair are in VALIDATION.md, "Run 20261117-233510".

### What it settled

- The KEV hard failures on `CVE-2026-24061` were an input gap, not a model habit: with the KEV
  listing in the input both arms say ACTIVELY_EXPLOITED. Had only one arm changed, the fix would
  have interacted with the JSON technique; it did not.
- Verdicts are a stable function of the input on this corpus: three runs, two input shapes, no
  verdict differs from the same arm's verdict in any other run. A verdict change in a later run is
  a signal, by the noise rule and now by three points.
- The two remaining hard failures (`CVE-2026-84282` PR, `CVE-2008-1113` AV) are the model misreading
  a vector it was given. The validator catches them; the input cannot fix them.

### What it exposed

- `first_attempt_valid` in `results.csv` conflates a schema failure with a `max_tokens` truncation:
  the native arm's single "miss" was the ceiling, repaired by the truncation retry with zero
  violations. The column keeps its meaning for the recorded runs; the next CSV-header change (a
  batch boundary, like the schema) adds a `first_attempt_outcome` column distinguishing
  schema / truncation / api-error, and COMPARISON.md reads the native 25/26 with that note until
  then.
- The 2026-11-13 pre-screen compared prose with the raw NVD record, not with the serialized
  `CveInput`, against the oracle rule of this document. `scripts/prose-prescreen.py` now uses
  `app input`; on the baseline runs the counts move by at most one output (17 / 14 and 14 / 13
  against 18 / 14 and 14 / 13), and the adjudicated letters are unaffected because they are
  judgements on lines, not on counts.
- Blind adjudication is now the layout, not an intention: section headers carry the run and the
  CVE and a per-section random token for the arm, sections are shuffled, the token map lives in
  `.arms-<date>.json`, and the table script restores the arm from the map. Per-arm pre-screen
  counts for a run under adjudication are not written into the docs until the letters are in.

## 2026-11-18 - Three points on the memory gap; the prompt arm retires from routine batches

### What happened

The blind adjudication of run `20261117-233510` gives native 7/26 and prompt 4/26 outputs with a
memory claim, after 9/26 vs 5/25 and 8/26 vs 4/26 on the baseline pair. Three runs, two input
shapes, one direction, a floor of one output. Details in VALIDATION.md, "Prose audit".

### What it decides

- The hypothesis of 2026-11-13 is a result: on this task native structured outputs produce prose
  with memory claims more often than prompt-only. The mechanism is not decided (forced fields, or
  more prose when the grammar does the formatting); the fix is the same either way and is decision
  7's business: a declared outlet for memory and a structured basis for severity adjustment, so a
  claim from outside the record is countable and cannot move `adjusted_severity` unannounced.
- The prompt arm has answered the two questions it was kept for (the comparison in COMPARISON.md
  and this gap). From the next batch on, `ARMS=native` is the default and the prompt arm runs only
  when the change under test is about the arms, for instance whether the memory outlet reduces
  native A more than prompt A. Halves the cost of a batch and of its adjudication.
- E (deployment assumptions) is reported as leaning the same way, not as settled: 0, 2, 4 gaps,
  small counts, and a pre-screen that misses half of them. It stays an input problem first: the
  deployment context is not in the record and must not be in the prose.

### Rules carried forward

- Blind layout for every adjudication (token headers, shuffled sections, map opened last); the
  first adjudication's non-blindness is noted wherever its numbers are cited.
- A pre-screen marker list is updated only between adjudications, never during one, and the added
  lines of one adjudication are the candidates for the next marker list: "long out of support",
  "experimental", "modern build / build pipeline / dependency graph" came in through added lines
  twice.

## 2026-11-18 - Schema `b6fac04f10752357`: a declared outlet for memory, a structured basis for severity

### What changed

One schema step at the batch boundary, after run `20261117-233510` had isolated the input effect:

- `background_knowledge` (top level, list of strings): facts the triage relies on that come from
  the model's own knowledge, one sentence each, empty when everything comes from the record. The
  system prompt gained one sentence: when you rely on something the record does not state, declare
  it here and nowhere else.
- `severity.adjustment_basis` (enum NONE, EXPLOIT_EVIDENCE, REACHABILITY, FIX_AVAILABILITY,
  RECORD_QUALITY, PRODUCT_LIFECYCLE, DEPLOYMENT_CONTEXT) with N11 (basis NONE exactly when adjusted
  equals NVD severity) and N12 (PRODUCT_LIFECYCLE or DEPLOYMENT_CONTEXT only with a non-empty
  outlet). Both HARD. Outputs recorded under the old schema replay with N11 unverifiable.
- `confidence` description: "Use LOW when data_gaps is non-empty" replaced by a rule about gaps that
  bear on the verdict (VALIDATION.md, decision 6, proposed 2026-11-12).
- `results.csv` gains three trailing columns: `first_attempt_outcome` (VALID / SCHEMA_INVALID /
  TRUNCATED / REFUSED / API_ERROR, so a truncation repaired by retry is no longer read as a schema
  failure), `adjustment_basis`, and the count of `background_knowledge` items. Raw results carry
  `first_attempt`. Older files read back with these absent.

### Why one step

Each of these changes the schema hash, and the hash is one element of the comparability key. Made
separately they would have cost a batch each with nothing to compare in between; made together
they move the key once, and the next run compares to `20261117-233510` on everything but the
schema. Decision 7 and decision 6 are closed by the same commit for that reason, not because they
are related.

### What the next run measures

- Does the outlet get used, and does prose A drop when it is? The adjudication for that run reads
  the "declared" line under each section and distinguishes a leak next to an empty outlet from one
  that duplicates a declared item.
- Does `adjustment_basis` ever say PRODUCT_LIFECYCLE or DEPLOYMENT_CONTEXT, and is N12 clean?
- Does the confidence distribution move toward the middle in the prompt arm, if the prompt arm runs?

The replay of the three recorded runs under the new validator is unchanged on every hard failure
(6, 5, 3), which is the check that the new invariants do not re-read old data.

### First run on the schema (20261118-113709, same day)

- The outlet is used in 19 of 26 outputs and takes deployment assumptions as readily as memory.
  That was not the design, and it is kept: a declared E is better than a buried one, and the input
  is still the right place for deployment context when it exists.
- N11 and N12 hold on all 26. The basis is self-reported, so N12 proves consistency between two
  fields the model wrote, not the truth of either; the audit still reads the declared sentences.
- Severity is adjusted in 14 outputs against 9, 10 and 10 in the earlier native runs, all five new
  adjustments on CVEs never adjusted before. A menu of reasons is read as an invitation. Verdicts
  did not move and priority moved by its floor, so no rule changes on one run; the second run on
  this schema decides whether 14 is a level. If it is, the fix is in the field description
  ("NONE is the expected value; adjust only when the record gives a reason"), not in the enum.
- Rule carried forward: a schema change that adds a structured choice is checked on its first run
  for the rate at which the non-default options are chosen, against the rate the free-text field
  implied before. Structure changes behaviour, not only measurement.

### The prose audit of that run (same day)

- Outputs with a memory claim in prose: 6 of 26 against 7 in the previous native run; with a
  deployment assumption: 7 against 6. Inside the floor both ways. The outlet did not empty the
  prose.
- What it did: 16 of the 21 memory or deployment lines in prose repeat a sentence the output
  declared in `background_knowledge`. 5 lines in 4 outputs are undeclared, one of them next to an
  empty outlet (`CVE-2008-1112`, "rejected by MITRE", where the record itself says Rejected and the
  attribution to MITRE is the memory).
- Decision: the gate's prose violation is redefined as an *undeclared* A or E. The provenance
  categories do not change; the adjudicator marks each A or E line declared or undeclared, the
  table reports both, and the per-run headline is the undeclared count (4 outputs here, against
  10 outputs with any A or E before there was anything to declare). Declared duplicates are
  handled by wording, not by a rule: the next field-description change says "declared knowledge is
  not repeated in prose", at the next schema boundary, together with whatever the second run on
  this schema says about the adjustment rate.
- Second run on this schema before any wording change: it gives the floor for the new schema's
  metrics (adjustment rate, declared count, undeclared count) and decides whether 14 adjusted
  outputs is a level. Native arm only.

### Replication on the schema (20261118-135633, same day)

- 13 adjusted outputs against 14: the adjustment rate under the structured basis is a level (half
  the corpus) and the floor for it is 1. Verdicts identical for the fifth run; N8 holds. The rate
  stays as it is until the golden set says the adjustments are wrong; the wording "NONE is the
  expected value" is not applied on a behaviour change that has not been shown to be an error.
- Grounding is byte-for-byte the same list of hard and soft lines as the first run on the schema,
  so the new validator's view of this corpus is stable.
- The basis label swaps between two true labels across runs (`CVE-2008-1115`), and a deployment
  reason can wear a REACHABILITY label (`CVE-2024-12366`). N12 is a consistency check between two
  self-reported fields; the audit reads the declared sentences. Carried forward unchanged.
- The replication pair S / R is the noise floor for every metric the new schema introduced
  (VALIDATION.md, "Run 20261118-135633"). The adjudication of R gives the floor for the undeclared
  count; the wording change for declared duplicates goes in after it, at the next schema boundary.

### The pair's prose audit (same day)

- Undeclared memory or deployment claims in prose: 4 outputs in each run, floor 0, different CVEs
  each time. Memory in prose: 6 and 6. Three quarters of the leaked lines repeat a declared
  sentence (16 of 21, 14 of 19).
- The wording change for declared duplicates ("declared knowledge is not repeated in prose") is
  justified by the pair and **deferred**: it moves the schema hash, and a moved hash costs two runs
  for a new floor. It is bundled with the next change that has to move the schema anyway (the
  attack fixtures of the trust-boundary work may need one; the priority rubric of decision 8 will).
  Until then the undeclared count is the headline and the declared duplicates are a known,
  measured style defect.
- The native-arm record after six runs: verdicts identical in every run on every CVE, hard
  grounding failures confined to two misread vectors, memory in prose a quarter of outputs under
  both schemas, undeclared memory 4 of 26 once there is a place to declare.

## 2026-11-18 - Decision 8 has its data; it is not adopted here

### What was measured

`scripts/priority-rubric.py` runs a priority rubric over every trustworthy recorded output (207
from six runs) and reports agreement with the model's own `priority`. VALIDATION.md, decision 8,
has the numbers: the written candidate 76%, a revised form that closes the candidate's CRITICAL gap
86%, description keywords deciding 5 outputs on one CVE, and 24 outputs where the model is one
step more urgent than either form.

### What it settles and what it leaves

- The rubric is a function of three things the pipeline already holds (`adjusted_severity`,
  `verdict`, exploit evidence in the input). Whatever form is adopted, `priority` is derivable, and
  the question "should the model generate it" has the same shape as for `mechanism`, with the
  opposite answer: `mechanism` was kept because it is deterministic only a third of the time,
  `priority` would be deterministic always.
- Adoption is the adjudicator's, after the regression layer of the golden set is labelled: the 24
  "model more urgent" outputs are either the rubric's blind spot or the model's inflation, and the
  labels decide, not the agreement rate. Contamination is on record: candidate written after
  seeing CVE-2026-86509, revised form after seeing all 207; the blind layer of the golden set is
  the only test of either that is not circular.
- If `priority` is computed rather than generated, that is a schema change, bundled with the
  wording change already waiting (declared knowledge not repeated in prose), one hash move.

### A note on the bundled schema step

A3a and A3b of the stage plan were made as one step. The input effect was isolated first (A1), and
the pair S / R gives the new schema its floor, so nothing is lost for grounding or for the outlet;
what is lost is a clean reading of the `confidence` description change on its own. Recorded in
VALIDATION.md, "Run plan".
