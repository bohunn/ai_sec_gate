# VALIDATION.md

Per-field validation specification for the triage output, and the record of how it was settled.
**This is NOT the golden set.** The golden set is a separate artifact covering only fields in the
"judgement" bucket, to be built after the rubric is written.

Method: oracle → assert → bucket. The bucket is a conclusion drawn from whether an oracle exists,
not a decision made up front.

Implementation: `validation/GroundingValidator` (per-field grounding) and `validation/Invariants`
(cross-field consistency), both producing `Finding`s collected in a `GroundingReport` that travels
with every `TriageResult`. `app ground <run-dir>` replays recorded runs through them offline.

## Ground rules

**The oracle is the input the model saw.** Every check compares the output against the
`CveInput` that was serialized into the user turn - never against the raw NVD record and never
against an outside source. A field is grounded when the model could have read it from what it
was sent. Two consequences:

- Data that exists in the record but was not in the input cannot be an oracle until it is plumbed
  into `CveInput`. The KEV listing (`cisaExploitAdd`) and the CVSS v2 `userInteractionRequired`
  flag were added for this reason on 2026-11-12 (`known_exploited`, `kev_date_added`, and the v2
  `user_interaction` slot).
- Runs recorded before an input field existed will fail checks on that field. That is a property
  of the replay, not of the model, and is noted where it happens below.

**Three statuses, not two.** A check reports `PASS`, `FAIL`, or `UNVERIFIABLE`. Unverifiable is
reported, never skipped, so that coverage ("attack_vector was checkable for 22 of 26 records") is
a number in every run rather than a silent gap in the denominator.

**Two severities.** `HARD` checks compare against data the model was told to copy or derive
mechanically; a failure is a grounding error. `SOFT` checks compare against a noisy oracle; a
failure is a flag for a reviewer. Soft failures never make a result ungrounded.

## Per-field table

Evidence column: replay of the two recorded runs (`20260919-000440`, `20260928-093807`), 103
trustworthy outputs, 26 CVEs × 2 arms × 2 runs minus one prompt-arm exhaustion. Both runs are
`claude-opus-5` (the second was confirmed against the API usage record; see
`data/runs/20260928-093807/PROVENANCE.md`). Where a CVE differs between runs, that is run-to-run
variance of one model on byte-identical input. **These numbers are in-sample**:
the asserts and invariants were tuned on the same outputs. They show the rules are consistent with
the recorded behaviour, not that they predict the next run. The next batch, with the new input
fields, is the hold-out.

| Field | Oracle (in `CveInput`) | Assert | When the oracle is absent | Severity | Bucket | Evidence |
|---|---|---|---|---|---|---|
| `cve_id` | `cve_id` | `out == in` | — | HARD | input verifiable | 103/103 pass |
| `summary` | none | prose audit only | — | — | judgement (advisory) | — |
| `affected.vendor` | CPE vendor segment of `affected[].criteria` | normalised name containment either way | no CPE → UNVERIFIABLE (40/103) | **SOFT** | input verifiable, noisy | 7 fails, all NVD CPE noise (see below) |
| `affected.product` | CPE product segment | as vendor | as vendor | **SOFT** | input verifiable, noisy | 7 fails, same records |
| `affected.component_type` | `cpe_categories` → allowed set per the field description | `out ∈ allowed(categories)` | empty → UNVERIFIABLE | **SOFT** | input verifiable, noisy | 7 fails, same records |
| `affected.vulnerable_versions` | version-like tokens in description + ranges + reference URLs | every version-like token in `out` (alphanumeric runs with a digit, joined by `. _ : + ~ -`: `2.4.1`, `A1_102b07`, `1:2.3-4`, a git SHA) appears in the input | no such token in `out` → UNVERIFIABLE (prose) | SOFT | input verifiable | 0 fails; 26 unverifiable after widening the token rule, which had wrongly called the `A1_102b07` fixture prose |
| `affected.fixed_version` | same text | null → PASS; else every version-like token appears in the input | no version-like token → UNVERIFIABLE | **HARD** | input verifiable | 103/103 pass (36 non-null, all grounded) |
| `weakness.mechanism` | CWE→mechanism table from the field description | `out ∈ map(in.cwe_ids)` | no mappable CWE → UNVERIFIABLE (judgement) | HARD | input verifiable when mapped | 32 checkable, 32 pass; 71 judgement |
| `weakness.cwe_ids` | `cwe_ids` | `set(out) ⊆ set(in)` (empty input ⇒ empty output) | — | HARD | input verifiable | 103/103 |
| `severity.nvd_base_score` | `cvss.base_score` | exact equality; no CVSS ⇒ `null` | — (the absence is itself the assert) | HARD | input verifiable | 103/103 |
| `severity.nvd_severity` | `cvss.base_severity` | equality; no CVSS ⇒ `UNKNOWN` | — | HARD | input verifiable | 103/103 |
| `severity.adjusted_severity` | rubric | golden set | — | — | judgement | — |
| `severity.adjustment_reason` | rubric | golden set + N2 | — | — | judgement | — |
| `exploitability.attack_vector` | `cvss.attack_vector` | enum equality (`ADJACENT_NETWORK`→`ADJACENT`) | no CVSS → UNVERIFIABLE (8) | HARD (all CVSS versions) | input verifiable | 2 fails: 1 record, v2 |
| `exploitability.privileges_required` | `cvss.privileges_required` | equality; v2 `authentication` NONE/SINGLE/MULTIPLE → NONE/LOW/HIGH | as above | HARD v3/v4, **SOFT v2** | input verifiable | 3 fails: CVE-2026-84282 |
| `exploitability.user_interaction_required` | `cvss.user_interaction` | `out == (UI != NONE)`; v4 PASSIVE/ACTIVE both mean true | no CVSS or v2 without flag → UNVERIFIABLE | HARD v3/v4, SOFT v2 | input verifiable | v3/v4: 0 fails; v2: 15 soft fails, all replay artefacts (flag was not in the input then) |
| `exploitability.exploit_maturity` | `known_exploited`; else `Exploit` reference tag; else description | KEV ⇒ `ACTIVELY_EXPLOITED`; Exploit tag ⇒ `≥ PROOF_OF_CONCEPT`; nothing ⇒ `≤ UNPROVEN` | description mentions exploitation but no structured evidence → UNVERIFIABLE | **HARD for KEV**, SOFT otherwise | input verifiable, layered | KEV: 4 fails on CVE-2026-24061 (replay artefact: `known_exploited` was not in the input); 9 soft fails = PoC claimed with no evidence |
| `exploitability.likelihood` | none | — | — | — | **judgement** | — |
| `impact.confidentiality` / `integrity` / `availability` | `cvss.*_impact` | equality; v2 NONE/PARTIAL/COMPLETE → NONE/LOW/HIGH | no CVSS → UNVERIFIABLE | HARD v3/v4, **SOFT v2** | input verifiable | v3/v4: 2 fails (CVE-2026-84282); v2: 12 soft fails |
| `impact.worst_case` | rubric | golden set | — | — | judgement (advisory) | — |
| `remediation.action` | — | golden set + N1, N5 | — | — | judgement | — |
| `remediation.detail` / `workaround` | — | prose audit | — | — | judgement (advisory) | — |
| `remediation.effort` | rubric | golden set | — | — | judgement | — |
| `verdict` | rubric | golden set + N4, N5, N6, N7 | — | — | judgement, **load-bearing** | — |
| `priority` | rubric | golden set + N8 | — | — | judgement, **advisory** | — |
| `confidence` | rubric | golden set + N7 | — | — | judgement | — |
| `rationale` | — | prose audit | — | — | judgement (advisory) | — |
| `data_gaps` | the input's CVSS / CWE / CPE presence | a gap that *denies* one of them while the input has it ("no CVSS metrics" next to CVSS 3.1) | — | SOFT | judgement with a negative check | 0 fails after narrowing; see decision 3 |
| `key_references` | `references[].url` | `set(out) ⊆ set(in)` and `|out| ≤ 3` | — | HARD | input verifiable | 103/103 |

### Reading the failures

The replay sorts the 11 hard failures into three kinds, and the kind matters more than the count:

| Kind | Cases | What it means |
|---|---|---|
| Model misread a v3.1 vector | CVE-2026-84282: `privileges_required` HIGH vs NONE (3×), `confidentiality` LOW vs HIGH (2×) | A real grounding error on a field the model was told to copy. This is what the validator exists to catch. |
| Model misread a v2 vector | CVE-2008-1113: `attack_vector` ADJACENT vs NETWORK (2×) | Same kind; v2 AV is unambiguous so it stays HARD. |
| Oracle added after the run | CVE-2026-24061: `exploit_maturity` PROOF_OF_CONCEPT / UNPROVEN while KEV-listed (4×) | The model never saw `known_exploited`. The failure is the reason the field was added; the next run will tell whether it fixes it. |

The 7 soft failures on `vendor` / `product` / `component_type` all sit on two records, CVE-2008-1113
and CVE-2008-1146, where NVD's CPE data names products that do not match the description (a Cisco
phone listed under `vocera_communications`; OpenBSD listed under `cosmicperl`, `darwin`,
`navision`). The model followed the description and was right. This is why CPE-derived checks are
SOFT and why `component_type` is not forced to `UNKNOWN` when the CPE disagrees (decision 1).

## Consistency invariants

Cross-field rules that need no oracle: a document violating one contradicts itself. Implemented in
`Invariants`, numbered here and in the finding paths (`invariant.N1a` …).

| Id | Invariant | Severity | Replay |
|---|---|---|---|
| N1a | `action == NO_FIX_AVAILABLE ⇒ fixed_version == null` | HARD | 103/103 |
| N1b | `fixed_version != null ⇒ action ∈ {UPGRADE, PATCH}` | HARD | 103/103 |
| — | `action == UPGRADE ⇒ fixed_version != null` | **rejected** | 3 counterexamples, all defensible (upstream commits, no release number). The implication runs one way only. |
| N2 | `adjusted_severity != nvd_severity ⇒ adjustment_reason` ≥ 20 chars | HARD | 103/103 |
| N3 | `nvd_severity == UNKNOWN ⇔ nvd_base_score == null` | HARD | 103/103 |
| N4 | `verdict == BLOCK ⇒ attack_vector == NETWORK` (system-prompt rule) | HARD | 20/20 |
| N5 | `verdict == BLOCK ⇒ fixed_version != null ∨ action ∈ {UPGRADE, PATCH}` (system-prompt rule) | HARD | 20/20 |
| N6 | `vuln_status == Rejected ⇒ verdict == ALLOW ∧ adjusted_severity == NONE` | HARD | 8/8 |
| N7 | `verdict == NEEDS_HUMAN_REVIEW ⇒ confidence == LOW` | HARD | 2/2 |
| N8 | `priority` within one step of `adjusted_severity` (CRITICAL∈{P0,P1}, HIGH∈{P0..P2}, MEDIUM∈{P1..P3}, LOW∈{P2,P3}, NONE=P3) | SOFT | 103/103 |
| N9 | `exploit_maturity == ACTIVELY_EXPLOITED ⇒ likelihood == HIGH` | SOFT | 8/8 |
| N10 | `verdict == ALLOW ⇒ adjusted_severity ∈ {NONE, LOW}` | SOFT | 8/8 |
| N11 | `adjusted_severity != nvd_severity ⇔ adjustment_basis != NONE` (from schema `b6fac04f10752357`; older outputs replay as unverifiable) | HARD | — |
| N12 | `adjustment_basis ∈ {PRODUCT_LIFECYCLE, DEPLOYMENT_CONTEXT} ⇒ background_knowledge != []` | HARD | — |
| — | `data_gaps != [] ⇒ confidence == LOW` (stated in the `confidence` field description) | **rejected** | violated by 50 of 87 outputs with gaps; see decision 6 |

## Decisions

Each was open on 2026-10-18. The answers below are implemented as the validator's defaults; each
names what to flip if the call goes the other way.

1. **`component_type`: reading 2 (infer from the description), CPE as a soft consistency check.**
   Forcing `UNKNOWN` would have discarded 31 of the 40 inferences made on no-CPE outputs (their
   correctness is a golden-set question) and would have been wrong on both records where CPE and
   description disagree. The field description
   already says this; the validator now agrees with it. *Flip:* change the severity in
   `GroundingValidator.affected()` to HARD.

2. **Oracle absent ⇒ `UNVERIFIABLE`, counted and printed, never skipped. Grounding failures are
   recorded, not fed back.** The retry loop repairs *shape*; whether a HARD grounding failure
   should buy another attempt is a cost question that needs a run with the new input fields first.
   Today a grounding failure changes the CSV row and the human output, not the exit code. *Flip:*
   in `TriageService`, convert `report.hardFailures()` to `Violation`s and treat them like schema
   violations (one more feedback round); add a `RetryPolicy` knob for it.

3. **`data_gaps` stays free text.** An enum would force the model to invent categories for the
   long tail (reachability, missing advisories, truncated CPE lists). The checkable part is the
   *negative*: a gap that denies the presence of CVSS, CWE or CPE while the input has it. That is
   implemented as a narrow SOFT check (leading negation + the subject + nothing but filler) after a
   wider heuristic flagged eleven legitimate gaps like "no affected version boundaries (CPE
   wildcard only)". Revisit after the golden set shows which gaps recur.

4. **`mechanism` stays in the schema.** The CWE map covers 32 of 103 outputs (31%); the model
   agreed with it every time. For the other 69% there is no mappable CWE and the field is a
   judgement call from the description, which is useful information the pipeline cannot derive.
   The "why generate it" test resolves to: it is only deterministic a third of the time.

5. **`priority` is advisory.** `GateCli` branches on `verdict` only. Two outputs were `WARN/P0`
   (CRITICAL, no published fix): urgent but un-blockable under the system-prompt rule. That is a
   meaningful combination, so priority must not be collapsed into verdict. N8 is a consistency
   band, not a rubric: it holds 103/103 today and still does not decide CVE-2026-86509, where the
   same model answered P1 and P2 across two runs, both inside the band. The rubric is open
   decision 8.

6. **Empty-fallback semantics**, one row per ❓ in the original table:
   - CPE empty → `vendor` / `product`: UNVERIFIABLE, null not required (the description may name
     them; 24 of 40 did).
   - CWE empty → `cwe_ids == []` (HARD, same subset assert); `mechanism` is judgement.
   - No CVSS → `nvd_base_score == null` and `nvd_severity == UNKNOWN` (HARD); vector-derived
     fields UNVERIFIABLE with no `UNKNOWN` requirement.
   - v2 only → `user_interaction_required` checked SOFT against the v2 flag when present; impacts
     and authentication mapped by convention, SOFT.
   - No fixed version in the input → `fixed_version` must be null or name a version that appears
     in the input (HARD). OSV is not wired in; it would only matter for versions absent from
     the input, which has not happened in 36 non-null outputs.
   - **Schema change made 2026-11-18 (schema `b6fac04f10752357`):** "Use LOW when data_gaps is
     non-empty" is gone from the `confidence` description, replaced by "Use LOW when a gap listed
     in data_gaps bears on the verdict itself, not merely on a detail". Over three runs the native
     arm followed the old sentence in 10 of 63 outputs with gaps and the prompt arm in 43 of 67;
     a rule one arm ignores and the other over-applies measured the arm, not the confidence. Made
     together with decision 7 so the schema hash moved once, at a batch boundary.

## Noise floor: the replication pair

Runs `20260919-000440` and `20260928-093807` are the same model, schema, prompt and corpus, so the
difference between them on any metric is the only measurement of run-to-run variance this project
has. Rule for every later run: a difference from the baseline **smaller than the spread between
these two runs on the same metric is noise** and is reported as noise. The spread is a floor from
two samples, not a confidence interval: below it is certainly noise; above it is not automatically
an effect.

| Metric (per arm) | native 0919 | native 0928 | spread | native A1 | prompt 0919 | prompt 0928 | spread | prompt A1 |
|---|---|---|---|---|---|---|---|---|
| trustworthy outputs | 26 | 26 | | 26 | 25 | 26 | | 26 |
| outputs with ≥1 hard grounding failure | 3 | 2 | 1 | 2 | 2 | 2 | 0 | 1 |
| hard-failure lines | 3 | 2 | 1 | 2 | 3 | 3 | 0 | 1 |
| soft-failure lines | 15 | 14 | 1 | 12 | 9 | 19 | 10 | 6 |
| outputs with ≥1 prose-audit candidate (pre-screen) | 18 | 14 | 4 | 14 | 14 | 13 | 1 | 12 |
| outputs with ≥1 A (memory), adjudicated | 9 | 8 | 1 | 7 | 5 | 4 | 1 | 4 |
| outputs with ≥1 E (deployment assumption), adjudicated | 4 | 5 | 1 | 6 | 4 | 3 | 1 | 2 |
| verdict BLOCK / WARN / ALLOW / NHR | 5 / 19 / 2 / 0 | 5 / 19 / 2 / 0 | 0 | 5 / 19 / 2 / 0 | 5 / 17 / 2 / 1 | 5 / 18 / 2 / 1 | 1 | 5 / 18 / 2 / 1 |
| priority P0 / P1 / P2 / P3 | 5 / 3 / 10 / 8 | 5 / 2 / 8 / 11 | 3 | 4 / 5 / 7 / 10 | 4 / 5 / 6 / 10 | 4 / 7 / 7 / 8 | 2 | 4 / 5 / 8 / 9 |
| confidence HIGH / MEDIUM / LOW | 6 / 16 / 4 | 6 / 16 / 4 | 0 | 8 / 15 / 3 | 3 / 9 / 13 | 3 / 7 / 16 | 3 | 4 / 8 / 14 |

Spread of a distribution row is half the L1 distance between the two runs (the number of outputs
that moved). A1 is run `20261117-233510`, the first run on the new input shape; its prose-audit
cells were filled only after the blind adjudication was in. The baseline pre-screen cells were
produced against the raw record on 2026-11-13; the pre-screen script now uses the serialized
`CveInput` and gives 17 / 14 and 14 / 13 for the same runs, and the A1 cells are under that oracle.

Two readings follow immediately. The verdict distribution is stable to the output across runs,
so a verdict change in a later run is a signal. The native-arm prose-candidate count moved by 4
between identical runs, which is exactly the "native 18 vs prompt 14" gap in the first run: the
pre-screen gap never stood above the noise floor. The adjudicated A count behaves differently: it
moves by 1 between runs and by 4 between arms, in both runs (see "Prose audit", adjudicated).

## Run 20261117-233510: the new input shape (A1)

One element of the comparability key moved: `input_shape_sha256` is `bc30ad24d93e88a4` (the input
now carries `known_exploited`, `kev_date_added` and the v2 `user_interaction_required`). Model
`claude-opus-5`, schema `81f1521f6e417e68`, system prompt and `corpus_frozen_at` are those of
the baseline pair. Both arms ran, 52 calls, replayed with `app ground`.

**Control question 1: does grounding change?** Per arm against the floor above:

- Hard failures: native 2 outputs / 2 lines (baseline 3 and 2 / 3 and 2): noise. Prompt 1 / 1
  (baseline 2 and 2 / 3 and 3): one fewer than either baseline, but the prompt floor on this metric
  is 0, so the rule has nothing to say; read as a direction, not an effect.
- The two remaining hard failures are the two misreads the baseline already had: `CVE-2026-84282`
  `privileges_required` HIGH against a v3.1 vector saying NONE, in both arms (5 of 8 baseline
  outputs had it; now 2 of 2); `CVE-2008-1113` `attack_vector` ADJACENT against a v2 vector saying
  NETWORK, native only (2 of 4 baseline outputs; now 1 of 2).
- The KEV artefact is gone in both arms. `CVE-2026-24061` had `exploit_maturity` PROOF_OF_CONCEPT
  (native) or UNPROVEN (prompt) in both baseline runs, 4 hard lines in all; with `known_exploited:
  true` in the input both arms say ACTIVELY_EXPLOITED and native confidence moved MEDIUM → HIGH.
  Same change in both arms is an input effect, not an interaction with the JSON technique.
- Soft failures: native 12 (15, 14; floor 1), prompt 6 (9, 19; floor 10). The native count is 2
  below both baselines, above its floor of 1, in the direction of fewer failures; the lines that
  remain are the CPE-noise vendor/product mismatches on `CVE-2008-1113` and `CVE-2008-1146` and two
  PROOF_OF_CONCEPT claims without an Exploit tag (`CVE-2024-28224`, `CVE-2026-79577`).

**Control question 2: do the judgement fields move?**

- Verdicts: identical to both baselines in both arms, output by output. Three runs, two input
  shapes, zero verdict changes.
- Priority: native 4 / 5 / 7 / 10 against a floor of 3 moved outputs; 4 against 0919, 3 against
  0928. The one P0 lost is `CVE-2026-79577` (sparse record, no CVSS, no CWE), P0 in both baseline
  runs and P1 now; the prompt arm had it at P1 in all three runs. Explicit `known_exploited: false`
  in the input is the obvious candidate cause; one output cannot confirm it. Prompt 4 / 5 / 8 / 9:
  1.5 and 2 against a floor of 2.5, noise.
- Confidence: native 8 / 15 / 3 against a floor of 0, 2 moved outputs. One of the two new HIGHs is
  the KEV CVE; the other (`CVE-2024-28088` against 0919, `CVE-2026-20963` against 0928) is not shared
  between the two comparisons. Prompt 1.5 and 2 against a floor of 2.5, noise.
- Adjusted severity: native identical to 0928, 2 moved against 0919 (floor 2); prompt 2 and 4.5
  against a floor of 2.5, the 4.5 being against the run that had the API error. Noise.

**Schema side.** Prompt-only 8/26 valid on the first attempt (7 and 5 before), 9 malformed and 9
extra fields; 4 of the 9 invented names had appeared in a baseline run (`" data_gaps"`,
`severity.exploit_maturity_note`, `exploitability.exploit_maturity_note`,
`severity.adjustment_reason_note`), 5 were new. Native 25/26: the one retry on `CVE-2026-76960` is
not a schema failure but the `max_tokens` ceiling (4,096; the output needed 4,999 tokens over two
attempts), repaired by the truncation retry. `first_attempt_valid` in `results.csv` does not
distinguish the two; see DECISIONS.md, 2026-11-18. Cost $2.37 against $1.47, median latency 25.4 s
against 14.0 s.

**Prose audit.** The pre-screen for this run is `data/prose_audit/candidates-20261118.md`,
generated by `scripts/prose-prescreen.py` against the serialized `CveInput` with the arm hidden
behind a per-section token (`.arms-20261118.json`, opened only after the last letter was in).
Adjudicated 2026-11-18, blind to arm this time: 53 pre-screen lines plus 14 added. Results under
"Prose audit", adjudicated, third point.

## Run 20261118-113709: the new schema (S)

One key element moved: `schema_sha256` is `b6fac04f10752357` (decisions 6 and 7). Model, input
shape, prompt apart from the one outlet sentence, and corpus are those of run `20261117-233510`
(A1). Native arm only, 26 calls, $1.54, median 15.0 s. Compared with the native arm of A1, floors
from the baseline pair's native arm.

| Metric | A1 native | S native | floor | reading |
|---|---|---|---|---|
| schema-valid on first attempt | 25/26 (one `max_tokens` truncation) | 26/26 | | |
| outputs with ≥1 hard grounding failure / lines | 2 / 2 | 1 / 2 | 1 | noise |
| soft-failure lines | 12 | 10 | 1 | 2 fewer, same CPE-noise lines |
| N11 / N12 | not in schema | 26/26 pass / 3/3 pass | | |
| verdict BLOCK / WARN / ALLOW / NHR | 5 / 19 / 2 / 0 | 5 / 19 / 2 / 0 | 0 | fourth identical run |
| outputs with adjusted ≠ NVD severity | 9 (baseline 10, 10) | **14** | 1 | **above floor** |
| priority P0 / P1 / P2 / P3 | 4 / 5 / 7 / 10 | 4 / 6 / 4 / 12 | 3 | at the floor |
| confidence HIGH / MEDIUM / LOW | 8 / 15 / 3 | 8 / 17 / 1 | 0 | expected from decision 6 |
| outputs declaring `background_knowledge` | not in schema | 19/26, 23 items | | |
| outputs with ≥1 prose pre-screen candidate / lines | 14 / 33 | 12 / 27 | 4 | pending adjudication |

**The outlet is used.** 19 of 26 outputs declare something, 23 sentences in all. They are of two
kinds, as the prose audit predicted: memory (A), such as "Sun Solaris 8 is a legacy operating system
released in 2000 and long past its support lifecycle", and deployment assumptions (E), such as
"Junos OS runs on Juniper routers ... commonly deployed at network perimeters" or "LangChain is ...
commonly embedded as an application dependency". The outlet was designed for A and takes E as
readily. That is acceptable for now: E is declared, countable and reviewable where before it was
buried in `rationale`. Whether prose A and E fall when the outlet is available is what the
adjudication of `candidates-20261118-schema.md` measures; mechanically, 10 of the 27 pre-screen
phrases also occur in a declared item of the same output, so at most 17 lines can be leaks next to
an outlet that does not cover them.

**`adjustment_basis` is used and consistent.** NONE 12, RECORD_QUALITY 5 (the two rejected records,
the two disputed ones, and CVE-2007-6703), REACHABILITY 3, EXPLOIT_EVIDENCE 2, PRODUCT_LIFECYCLE 2
(CVE-2008-1115, CVE-2008-1146), DEPLOYMENT_CONTEXT 1 (CVE-2026-46251), FIX_AVAILABILITY 1. N11 and
N12 pass on every output: the three outside-knowledge bases are declared. The basis is the model's
own label, so N12 checks consistency, not truth: CVE-2002-1774 says RECORD_QUALITY (the record is
disputed, so the label is defensible) while its declared knowledge is a deployment claim ("a
consumer desktop endpoint product ... not a library or build-time dependency"). The reviewer now
sees both; before this schema they saw a sentence.

**The menu invites adjusting.** Five CVEs that were never adjusted in three runs are adjusted now
(`CVE-2007-6252` MEDIUM → HIGH, `CVE-2008-1146` MEDIUM → LOW, `CVE-2020-1631` HIGH → CRITICAL,
`CVE-2024-36423` MEDIUM → HIGH, `CVE-2026-84282` MEDIUM → LOW), none went the other way, and the
baseline pair's native arm agreed with itself on this metric exactly (10 and 10). Offering a list of
reasons to adjust reads as an invitation to find one. No verdict changed, and the priority
distribution moved by exactly its floor, so the gate's decision did not; but a second run on this
schema is needed before 14 is called the new level rather than a first-run jump.

**Hard failures.** The one output is `CVE-2026-84282` again, now with two misreads of its v3.1
vector (`privileges_required` HIGH against NONE, as in every run; `impact.confidentiality` LOW
against HIGH, new). The `CVE-2008-1113` v2 misread did not recur. The KEV field holds.

**Prose audit.** `data/prose_audit/candidates-20261118-schema.md`, 12 sections, 27 lines, each
section headed by a "declared background_knowledge" line when the output declared any, so the
adjudicator can tell a leak next to an empty outlet from one that duplicates a declared item.
Adjudication pending.

## Prose audit: provenance, not truth

The judgement bucket's prose fields (`summary`, `adjustment_reason`, `worst_case`, `detail`,
`workaround`, `rationale`) have no mechanical oracle, and the invariants cannot ask where a sentence
came from. The audit that covers them asks one question per factual claim: **was this in the
input?** Not whether it is true. A true fact from the model's memory breaks "do not fill gaps from
memory" exactly as a false one does, passes every truth check, and gets a nod from a human reviewer
because "that's right". Only a provenance test catches it.

**Protocol.** For each output, extract the factual claims from the six prose fields and put each
in one of five categories, regardless of truth:

| | Category | Test |
|---|---|---|
| A | **memory** | a fact about the world the record does not contain ("the DIR-895L is end-of-life") |
| B | paraphrase | restates something that is in the input |
| C | generic | triage language that asserts nothing about this CVE ("upgrade when a fix is available") |
| D | inference | follows from the input alone. Deciding test: *would a reader with only the input and no knowledge of the world reach it?* Published 2001 → "old" is arithmetic, yes. "DIR-895L" → end-of-life needs D-Link's support calendar, no. |
| E | **deployment assumption** | a claim about how the component is deployed ("internet-exposed", "commonly") that neither the record nor training data can supply. Closest to the verdict, so the most dangerous class for a gate. |

D is allowed and wanted: it separates reasoning from recall without forbidding the model to think.
A is what "do not fill gaps from memory" forbids. E belongs in the input, in the comparability key,
or outside the LLM; never in prose.

**Metric.** Share of outputs with at least one A claim, and separately with at least one E claim,
per run × arm and per field. The split by arm is kept on purpose. In the pre-screen the native
arm has more flagged outputs than the prompt arm in the first run (18 of 26 vs 14 of 25); in the
second run, same model and same input, the difference is one output (14 vs 13 of 26). The
pre-screen therefore could not decide the hypothesis from COMPARISON.md (constrained decoding, by
forcing every field to be filled, may invite filling from memory). Adjudication could.

**Adjudicated (2026-11-17).** All 136 pre-screen lines of `data/prose_audit/candidates-20261113.md`
were categorised by hand, 27 lines the pre-screen missed were added (marked "added"), and
`scripts/prose-audit-table.py` tabulates the file:

| run | arm | outputs | ≥1 A | ≥1 E | A lines | E lines | lines |
|---|---|---|---|---|---|---|---|
| 20260919-000440 | native | 26 | 9 (35%) | 4 (15%) | 21 | 5 | 49 |
| 20260919-000440 | prompt | 25 | 5 (20%) | 4 (16%) | 14 | 5 | 32 |
| 20260928-093807 | native | 26 | 8 (31%) | 5 (19%) | 22 | 7 | 47 |
| 20260928-093807 | prompt | 26 | 4 (15%) | 3 (12%) | 16 | 4 | 35 |

Three readings:

- **A differs by arm, in both runs, above the noise floor.** Native has 4 more outputs with a memory
  claim than prompt in each run, while the same arm moves by 1 between runs. In each run every
  output with an A in the prompt arm also has one in the native arm; the reverse does not hold.
  `CVE-2002-1774` and `CVE-2024-28224` carry memory claims in the native arm only, in both runs. The
  gap survives when the 27 adjudicator-added lines are dropped and only the mechanical, arm-blind
  pre-screen lines count: 8 vs 4 and 6 vs 3. The hypothesis stands, with the caveats below.
- **E leans the same way, less firmly.** 4 vs 4 and 5 vs 3: one run with no gap, one with a gap of
  2 against a floor of 1. Deployment assumptions appear in roughly one output in six and only in
  the two fields that feed the verdict: `adjustment_reason` (13 lines) and `rationale` (8). None in
  `summary`, `detail`, `workaround` or `worst_case`.
- **Where A lands.** `summary` 20, `rationale` 16, `adjustment_reason` 15, `workaround` 12,
  `detail` 6, `worst_case` 4. `adjustment_reason` has the worst ratio: 28 of its 39 flagged lines
  are A or E, and it is the field N8 reads through `adjusted_severity`. This is the data behind
  the second question of decision 7.

**Third point (2026-11-18), run 20261117-233510, adjudicated blind to arm.** 53 pre-screen lines
and 14 added lines, headers carrying a random token instead of the arm, sections shuffled.

| run | arm | outputs | ≥1 A | ≥1 E | A lines | E lines | lines |
|---|---|---|---|---|---|---|---|
| 20261117-233510 | native | 26 | 7 (27%) | 6 (23%) | 15 | 6 | 41 |
| 20261117-233510 | prompt | 26 | 4 (15%) | 2 (8%) | 7 | 2 | 25 |

- A: gap of 3 (4 if the one disputed `A?` on CVE-2026-86509 counts), same direction as the
  baseline pair's 4 and 4, against a floor of 1. On the arm-blind pre-screen lines alone 5 vs 3.
  `CVE-2002-1774` carries a memory claim in the native arm only for the third run running;
  `CVE-2024-28224` likewise (its A1 claim is an added line). The prompt arm's only native-free A is
  `CVE-2026-46251` ("experimental", four lines), which both arms produced in the baseline.
  Three runs, two input shapes, one direction: the hypothesis that constrained decoding invites
  filling from memory is a result of this experiment, not a hypothesis under doubt. What the three
  points cannot separate is *why*: a field that must be filled, or a model that writes more when the
  grammar does the formatting (native prose carries more flagged lines in every run: 49 / 47 / 41
  against 32 / 35 / 25).
- E: 6 vs 2, the largest gap of the three runs; on pre-screen lines alone 3 vs 1. Over three runs
  native E is 4, 5, 6 and prompt 4, 3, 2. The direction is consistent and two of three gaps exceed
  the floor, so E is read as leaning the same way as A, with less weight: the pre-screen catches E
  poorly (half of this run's E lines were added by the adjudicator) and the counts are small.
- Fields: `summary` and `rationale` carry most A again; E stays in `rationale` and
  `adjustment_reason`.

Caveats. The noise floor is two samples. The first adjudication (baseline pair) saw the arm in each
section header and was not blind; the third was. The pre-screen-only check is the control for the
first and a consistency check for the third.
Two lines are disputed (`A?`), both the conditional "replace the device if it is end-of-life" on
CVE-2026-86509; neither changes any count, because both outputs carry other A lines. A third run on
the new input shape (the A1 batch) adds a third point to the floor before the gap is called a
property of constrained decoding rather than of this corpus. The frequent A on CVE-2007-6252
("Internet Explorer", "Windows" for a record that says MSIE) is harmless memory and is counted all
the same: the metric is per output, so one such CVE moves it by at most one.

**Entry 1 (2026-11-13), CVE-2026-86509.** `adjustment_reason` says the device is an "end-of-life
consumer router" (run 0928) / "legacy consumer router" (run 0919); `remediation.detail` says
"replace the device if it is end-of-life" in both. The frozen record contains none of
end-of-life, EOL, legacy or discontinued. The claim is true: the DIR-895L is past vendor support.
Three things make it the reference case:

- It landed in the field that justifies the downgrade CRITICAL → HIGH. A fact from memory moved
  `adjusted_severity`, which N8 then uses to bound `priority`. Judgement fields are load-bearing by
  adjacency. N2 passed because it checks the length of a reason, not its origin; that is what N2
  is for, and it is why this audit is a separate mechanism, not a future invariant.
- Both runs, both arms, the same claim. Agreement between runs is not grounding; here it is the
  signature of training data, the one input to this pipeline that is neither frozen nor
  controlled. "Do not fill from memory" is a security control, not a style rule.
- An automatic pre-screen (`data/prose_audit/candidates-20261113.md`: world-knowledge markers,
  deployment-assumption markers, dates and capitalised names absent from the input) flags 59 of 103
  outputs, including "legacy" / "end-of-life" on CVE-2001-1533, CVE-2002-1774 and CVE-2007-6252,
  where the publication year is in the input and the D test decides. The list is deliberately wide
  and is evidence of the same class as `data/runs/`; the adjudicated version (same file, letters
  filled in) is the artifact without which the metric cannot be reproduced.

**Decision 7 (decided 2026-11-18, schema `b6fac04f10752357`).** Device end-of-life is useful to
triage, and three adjudicated runs show the model using such knowledge in a quarter to a third of
native-arm outputs whatever the prompt says. The ban stays for prose and memory gets a legal
outlet: `background_knowledge`, a list of short declarative sentences the model asserts from
outside the record. The outlet does *not* make the rule mechanically checkable: a leak into prose
still needs the provenance audit. What it gives is three other things: memory is declared and
countable without extraction (`background_knowledge` column in the CSV, "declared" line per section
in the pre-screen); the reviewer gets a ready "verify these" list; and a leak into prose next to an
empty outlet is a double violation, so the audit has a sharper definition. Labelled hallucinations
are still hallucinations; they are now visible ones.

The second question is answered the same way `mechanism` was: the basis of a severity adjustment is
an enum, `adjustment_basis` (NONE, EXPLOIT_EVIDENCE, REACHABILITY, FIX_AVAILABILITY,
RECORD_QUALITY, PRODUCT_LIFECYCLE, DEPLOYMENT_CONTEXT), with two invariants. N11: the basis is NONE
exactly when adjusted equals NVD severity. N12: a basis of PRODUCT_LIFECYCLE or DEPLOYMENT_CONTEXT
is legal only when `background_knowledge` is non-empty. "Memory must not move severity" is now a
check: memory may move it, declared, and the reviewer sees both the move and the claim it rests
on. DEPLOYMENT_CONTEXT is expected to stay at zero, because the input carries no deployment context
(E in the prose audit); every occurrence is reviewed, and the field is the place such a claim will
land when it is supplied through the input one day. The system prompt gained one sentence pointing
at the outlet. Outputs recorded under the old schema replay with N11 unverifiable and no N12.

**Open decision 8 (blocks the golden set).** A priority rubric that decides a case the N8 band
leaves open. Test case: CVE-2026-86509 (WARN, adjusted HIGH, published exploit in the description,
no fix) came back P1 three times and P2 once across two runs of the same model; both are inside
the HIGH band.
A rubric that does not return exactly one of them for this record is not finished. Candidate for
discussion, not adopted: P0 when BLOCK or KEV-listed; P1 when adjusted ≥ HIGH and the input carries
exploit evidence (KEV, Exploit tag, or the description); P2 when adjusted HIGH without such evidence
or MEDIUM; P3 otherwise. On 86509 the description says the exploit is published, so this candidate
returns P1. The golden set cannot be built until a rubric is adopted, because the oracle for
`priority` would otherwise be whoever labels it that day.

**Run plan.** The next run must not change three things at once. Three axes were pending: the new
input fields (KEV, v2 user interaction), the `confidence` description change, and the memory outlet
of decision 7. The intermediate run on the **same model as the baseline** (`claude-opus-5`) with
the *old* schema and the *new* input (`20261117-233510`) isolated the KEV effect. The two schema
changes were then made as one step (schema `b6fac04f10752357`, 2026-11-18), so the next run moves one
key element again: the schema. It runs the native arm by default (DECISIONS.md, 2026-11-18); the
prompt arm is added only to test whether the outlet changes the memory gap by arm.

## Running it

```bash
app ground data/runs/20260928-093807          # per-check table, hard failures
app ground data/runs/20260928-093807 --soft   # also list soft failures
```

Per-triage: the human output ends with a `Grounding:` summary and lists failures; the CSV row has
four new trailing columns (`grounding_hard_fail`, `grounding_soft_fail`,
`grounding_unverifiable`, `first_hard_fail_path`); the raw JSON carries the full report.

Replay caveat: the oracle is the *current* `CveInput`, so a replay of a run recorded before an
input field existed will fail on that field (KEV, v2 user interaction). Compare like with like.
