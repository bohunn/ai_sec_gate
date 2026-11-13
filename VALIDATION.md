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
trustworthy outputs, 26 CVEs × 2 arms × 2 runs minus one prompt-arm exhaustion.

| Field | Oracle (in `CveInput`) | Assert | When the oracle is absent | Severity | Bucket | Evidence |
|---|---|---|---|---|---|---|
| `cve_id` | `cve_id` | `out == in` | — | HARD | input verifiable | 103/103 pass |
| `summary` | none | prose audit only | — | — | judgement (advisory) | — |
| `affected.vendor` | CPE vendor segment of `affected[].criteria` | normalised name containment either way | no CPE → UNVERIFIABLE (40/103) | **SOFT** | input verifiable, noisy | 7 fails, all NVD CPE noise (see below) |
| `affected.product` | CPE product segment | as vendor | as vendor | **SOFT** | input verifiable, noisy | 7 fails, same records |
| `affected.component_type` | `cpe_categories` → allowed set per the field description | `out ∈ allowed(categories)` | empty → UNVERIFIABLE | **SOFT** | input verifiable, noisy | 7 fails, same records |
| `affected.vulnerable_versions` | version numbers in description + ranges + reference URLs | every `\d+(\.\d+)+` token in `out` appears in the input | no numbers in `out` → UNVERIFIABLE (prose) | SOFT | input verifiable | 0 fails, 47 unverifiable |
| `affected.fixed_version` | same text | null → PASS; else every version token appears in the input | no version token → UNVERIFIABLE | **HARD** | input verifiable | 103/103 pass (36 non-null, all grounded) |
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
   meaningful combination, so priority must not be collapsed into verdict. The rubric for the
   golden set is the N8 band; N8 holds 103/103 today.

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
   - **Schema change proposed, not made:** drop "Use LOW when data_gaps is non-empty" from the
     `confidence` field description. The model ignores it in 57% of cases and the rule is too
     strict (every realistic record has some gap). Removing it changes the schema hash and so the
     comparability of runs; do it at the start of the next batch, not between runs.

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
