# ai_sec_gate

An experiment testing whether an LLM's CVE triage verdict is reliable enough for a CI pipeline to
act on automatically.

## Why

In real triage work, dependency scanners produce a steady stream of CVEs, and most of the effort
goes into sorting through noise before a sound decision can be made. An LLM can do that first pass,
but a CI gate can only act on its output if the output is machine-readable every time and grounded
in the record rather than in the model's memory. This project measures how close that gets.

## Key results

26 CVEs, one run each, `claude-opus-5`. Both arms used the same system prompt, the same schema and
the same frozen NVD records. The only difference between them is how JSON output is forced.

| | Prompt-only | Native structured outputs |
| --- | --- | --- |
| Schema-valid on first attempt | 7/26 | 26/26 |
| Usable after one retry round with validator feedback | 25/26 | 26/26 |
| Total attempts | 43 | 26 |
| Cost | $2.32 (+75%) | $1.32 |
| Median latency per CVE | 26.4 s (2x) | 12.6 s |

Retries make prompt-only usable, but every retry is a full extra call, so it costs more and takes
longer. Full breakdown in [COMPARISON.md](COMPARISON.md).

## How it works

1. **NVD fetch** - the CVE record is fetched from the NVD API (or read from the frozen corpus in
   `data/corpus/`) and normalized into a `CveInput`.
2. **Schema generation** - the JSON schema is generated from the `CveTriage` Java record by
   `SchemaGenerator`, so the schema and the code cannot drift apart.
3. **Claude with structured outputs** - the record is sent as untrusted data, and the schema is
   enforced through constrained decoding (or, in the prompt-only arm, requested in the prompt).
4. **Validation** - the response is checked against the schema, then grounded against the input
   it was generated from: copied fields (`nvd_base_score`, `cwe_ids`, `key_references`), fields
   derived from the CVSS vector, `fixed_version` against the version numbers the input actually
   contains, `exploit_maturity` against the KEV listing, plus ten cross-field invariants. Each
   check reports pass, fail or unverifiable; see [VALIDATION.md](VALIDATION.md).
5. **Retry with feedback** - if schema validation fails, the violations go back to the model as a
   follow-up turn. When retries run out, the result is marked as a broken gate rather than passed.
   Grounding findings are recorded with the result (CSV, JSON, human output) and do not trigger a
   retry or change the exit code; see VALIDATION.md, decision 2.

The CLI exits with `0` (clean), `1` (blocked) or `2` (gate broken), so a pipeline can branch on the
result.

## Known limitations

- `fixed_version` is verified only as far as the input goes: a version number must appear
  somewhere in the record the model was sent. A real fix release the record does not mention
  cannot be told apart from an invented one without a second source (OSV).
- Prose fields can carry true facts from the model's memory (a device being end-of-life, say)
  that the record never stated. No truth check catches that; the prose audit in VALIDATION.md is a
  provenance check and is manual. Across three runs it finds such a claim in 27–35% of native-arm
  outputs and 15–20% of prompt-only outputs.
- One run per CVE is a sample, not a property. Model variance changes first-attempt results between
  runs, even on identical inputs.
- Records without CPE configuration data give no oracle for `vendor`, `product` and
  `component_type`; the model infers them from the description and the validator reports them as
  unverifiable rather than wrong. These are the records where triage is hardest.

## Next steps

- Add OSV as a second source for fixed and introduced version ranges, to verify fixed versions
  the NVD record does not mention.
- The schema changes as one step at the next batch boundary (decision 7: a declared outlet for
  memory and a structured basis for severity adjustment), measured against the three recorded runs.
  Three runs now agree that the native arm fills prose from memory more often than prompt-only
  (VALIDATION.md, "Prose audit"); later batches run the native arm alone unless the change under
  test is about the arms.
- Repeat the prose audit on the next batch: the adjudicated first two runs show memory claims in
  about a third of native-arm outputs against a fifth or less in the prompt arm (VALIDATION.md,
  "Prose audit"), and a third run decides whether that is a property of constrained decoding.
- Threat-model the trust boundary, in particular forged assistant turns when message history is
  built from untrusted data.
- Repeat the comparison with several runs per CVE to put an error bar on the results.

## Repository guide

| File | Contents |
| --- | --- |
| [DECISIONS.md](DECISIONS.md) | Design decisions and trade-offs |
| [VALIDATION.md](VALIDATION.md) | Per-field grounding specification, invariants, replay results |
| [COMPARISON.md](COMPARISON.md) | Full two-arm results |
| [FINDINGS_FIRST_STEP_API.md](FINDINGS_FIRST_STEP_API.md) | Notes from the first API experiments |
| [SELECTED_CVES.md](SELECTED_CVES.md) | The 26-CVE corpus and why each was chosen |

## Running it

Prerequisites: JDK 21 and an Anthropic API key. Gradle is provided by the wrapper.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
./gradlew installDist -q && app/build/install/app/bin/app CVE-2024-28088
```

Run it from the repository root, because the CLI reads `data/` relative to the working directory.
Use `--arm prompt|native` to choose the technique, and `app help` lists all options. To run the
full two-arm batch, use `scripts/run-batch.sh` (`RUNS=3 scripts/run-batch.sh` repeats each CVE).
`app ground data/runs/<stamp>` replays a recorded run through the grounding validator without
calling the API. `scripts/prose-prescreen.py <stamp> --write data/prose_audit/candidates-<date>.md`
writes a blind prose pre-screen of a run, `scripts/prose-worksheet.py` renders it next to the
inputs for adjudication, and `scripts/prose-audit-table.py` tabulates the adjudicated file.

---

Status: experimental, personal learning project.
