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
| Median latency per CVE | 26.3 s (2x) | 12.6 s |

Retries make prompt-only usable, but every retry is a full extra call, so it costs more and takes
longer. Full breakdown in [COMPARISON.md](COMPARISON.md).

## How it works

1. **NVD fetch** - the CVE record is fetched from the NVD API (or read from the frozen corpus in
   `data/corpus/`) and normalized into a `CveInput`.
2. **Schema generation** - the JSON schema is generated from the `CveTriage` Java record by
   `SchemaGenerator`, so the schema and the code cannot drift apart.
3. **Claude with structured outputs** - the record is sent as untrusted data, and the schema is
   enforced through constrained decoding (or, in the prompt-only arm, requested in the prompt).
4. **Validation** - the response is checked against the schema. Fields that copy the input
   (`nvd_base_score`, `cwe_ids`, `vendor`, `product`) are kept so a grounding check can compare
   them against the source record.
5. **Retry with feedback** - if validation fails, the violations go back to the model as a
   follow-up turn. When retries run out, the result is marked as a broken gate rather than passed.

The CLI exits with `0` (clean), `1` (blocked) or `2` (gate broken), so a pipeline can branch on the
result.

## Known limitations

- `fixed_version` cannot be verified. NVD often does not publish one, and a plausible invented
  version number passes every check.
- One run per CVE is a sample, not a property. Model variance changes first-attempt results between
  runs, even on identical inputs.
- Records without CPE configuration data give no signal for `component_type`, so those fields fall
  back to `UNKNOWN`. These are the records where triage is hardest.

## Next steps

- Add OSV as a second source for fixed and introduced version ranges, so `fixed_version` can be
  verified.
- Threat-model the trust boundary, in particular forged assistant turns when message history is
  built from untrusted data.
- Repeat the comparison with several runs per CVE to put an error bar on the results.

## Repository guide

| File | Contents |
| --- | --- |
| [DECISIONS.md](DECISIONS.md) | Design decisions and trade-offs |
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

---

Status: experimental, personal learning project.
