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

`fixed_version` is the highest-risk field and the only one no validator can check. NVD frequently
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
