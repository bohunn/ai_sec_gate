# Golden set (proposal, 2026-11-18; nothing fetched or labelled yet)

Two layers, marked apart, both labelled on the judgement fields only (`verdict`, `priority`,
`adjusted_severity`, `confidence`, `mechanism`, `component_type`, `remediation.action`,
`exploit_maturity`, `likelihood`), one sentence of "why" per label, labeller and date. Copied and
derived fields have an oracle already (VALIDATION.md); they are not labelled.

## Layer 1: regression (contaminated by design)

10–15 CVEs from the frozen corpus. Preference order: the records on which the native arm disagreed
with itself across the six runs (`CVE-2007-6252`, `CVE-2008-1146`, `CVE-2026-46251`,
`CVE-2026-84282`, `CVE-2024-36423`, `CVE-2024-28224`, `CVE-2026-79577`, `CVE-2026-86509`,
`CVE-2024-12366`), then one record per stratum not yet covered. The header of the label file says
which recorded outputs the labeller had seen. Labels are written before any run on a schema that
computes `priority` (decision 8), so the model never sees the rubric before the labels exist.

## Layer 2: blind hold-out

8–12 CVEs **not** in the corpus. Selection criteria, fixed here before any record is fetched:

- one record per stratum of `data/corpus.csv` (control, sparse, reject, disputed, metrics, scale,
  cwe, adversarial, stability), chosen by the stratum's structural criteria (status, which CVSS
  versions, CWE present or `noinfo`, CPE count, description length) and **not** by reading the
  description;
- published after `corpus_frozen_at` (2026-09-18) where the stratum allows it, so the records are
  as fresh as the corpus's 2026 records were when selected;
- fetched with `app freeze` extension (records appended, `corpus_frozen_at` kept, per-record
  sha256), then labelled **before the first model call on any of them**;
- the label file's header carries the fetch date and the labelling date, in that order.

## Labelling protocol

One file per layer, `data/golden/<layer>.csv`: `cve_id, field, label, why, labeller, date`. The
disagreement protocol between model and label admits three outcomes: the model is wrong, the label
is wrong (recorded as such, label corrected, the original kept with a strike), or both are
defensible (the field gets an interval, not a point). The last two are the material for the
threshold interval of `app eval`.

## Threshold is an interval

`app eval <run-dir>` reports, per field, the share of outputs whose value falls inside the label
(point or interval), separately for the load-bearing fields (`verdict`, `priority`,
`adjusted_severity`) and the advisory ones. RUNS ≥ 3 bounds the model's variance; nothing here
bounds the labeller's or the 8–12 sample's. The accepted width is written next to the first result,
with what would narrow it (more hold-out records, a second labeller).
