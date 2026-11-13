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
trustworthy outputs, 26 CVEs × 2 arms × 2 runs minus one prompt-arm exhaustion. The two runs are
two models: `20260919-000440` is `claude-opus-5`; `20260928-093807` is attributed to
`claude-sonnet-5` with the uncertainty described in `data/runs/20260928-093807/PROVENANCE.md` (its
manifest says `claude-opus-5`). Where a CVE differs between runs, that is a cross-model difference
first. **These numbers are in-sample**:
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
   two models answered P1 and P2 inside the same band. The rubric is open decision 8.

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
per model × arm and per field. The split by arm is kept on purpose. In the pre-screen the native
arm has more flagged outputs than the prompt arm for Opus (18 of 26 vs 14 of 25); for Sonnet the
difference is one output (14 vs 13 of 26) and is noise. The Opus gap is the hypothesis for
COMPARISON.md: constrained decoding, by forcing every field to be filled, may invite filling from
memory. Adjudication should test it on Opus and not read the Sonnet pair as confirmation.

**Entry 1 (2026-11-13), CVE-2026-86509.** `adjustment_reason` says the device is an "end-of-life
consumer router" (run 0928) / "legacy consumer router" (run 0919); `remediation.detail` says
"replace the device if it is end-of-life" in both. The frozen record contains none of
end-of-life, EOL, legacy or discontinued. The claim is true: the DIR-895L is past vendor support.
Three things make it the reference case:

- It landed in the field that justifies the downgrade CRITICAL → HIGH. A fact from memory moved
  `adjusted_severity`, which N8 then uses to bound `priority`. Judgement fields are load-bearing by
  adjacency. N2 passed because it checks the length of a reason, not its origin; that is what N2
  is for, and it is why this audit is a separate mechanism, not a future invariant.
- Both models, both runs, the same claim. Agreement between models is not grounding; here it is
  the signature of shared training data, the one input to this pipeline that is neither frozen nor
  controlled. "Do not fill from memory" is a security control, not a style rule.
- An automatic pre-screen (`data/prose_audit/candidates-20261113.md`: world-knowledge markers,
  deployment-assumption markers, dates and capitalised names absent from the input) flags 59 of 103
  outputs, including "legacy" / "end-of-life" on CVE-2001-1533, CVE-2002-1774 and CVE-2007-6252,
  where the publication year is in the input and the D test decides. The list is deliberately wide
  and is evidence of the same class as `data/runs/`; the adjudicated version is the artifact
  without which the metric cannot be reproduced.

**Open decision 7 (before the golden set).** Device end-of-life is useful to triage. Two honest
answers: keep the ban and audit for leaks, or give memory a legal outlet, such as a
`background_knowledge` list of claims the model asserts from outside the record. The outlet does
*not* make the rule mechanically checkable: a leak into prose still needs claim extraction. What it
gives is three other things: memory is declared and countable without extraction; the reviewer gets
a ready "verify these" list; and a leak into prose next to an empty outlet becomes a double
violation, so the audit gets a sharper definition. Cost: a schema change and labelled hallucinations
that are still hallucinations.

A second question hides under the first: "memory must not move severity" cannot be checked while
`adjustment_reason` is a sentence. For it to be checkable, the *basis* of the adjustment would have
to be structured, the same move that made `mechanism` an enum next to `summary`: for instance an
`adjustment_basis` enum (exploit evidence, reachability, fix availability, product lifecycle,
deployment context, none) with the invariant that a basis of "product lifecycle" or "deployment
context" is only legal when declared in the outlet. Not decided; recorded so the golden set is
built with the answer, not before it.

**Open decision 8 (blocks the golden set).** A priority rubric that decides a case the N8 band
leaves open. Test case: CVE-2026-86509 (WARN, adjusted HIGH, published exploit in the description,
no fix) came back P1 three times and P2 once across the two models; both are inside the HIGH band.
A rubric that does not return exactly one of them for this record is not finished. Candidate for
discussion, not adopted: P0 when BLOCK or KEV-listed; P1 when adjusted ≥ HIGH and the input carries
exploit evidence (KEV, Exploit tag, or the description); P2 when adjusted HIGH without such evidence
or MEDIUM; P3 otherwise. On 86509 the description says the exploit is published, so this candidate
returns P1. The golden set cannot be built until a rubric is adopted, because the oracle for
`priority` would otherwise be whoever labels it that day.

**Run plan.** The next run must not change three things at once. Three axes are pending: the new
input fields (KEV, v2 user interaction), the `confidence` description change, and the memory outlet
of decision 7. An intermediate run on `claude-sonnet-5` with the *old* schema and the *new* input
isolates the KEV effect for a fraction of a dollar; the schema changes go in the run after it, as
one documented step. Single runs are cheap; mixed causes are expensive.

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
