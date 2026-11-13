## Output set groupings

extern verifiable:
- affected -> vendor
- affected -> product
- affected -> component_type
- affected -> vulnerable_versions
- affected -> fixed_version
- exploitability -> exploit maturity

input verifiable:
- weakness -> cwe_ids
- severity -> nvd_base_score
- severity -> nvd_severity
- remediation -> action
- exploitability -> attack_vector
- exploitability -> privileged_required
- exploitability -> user_interaction_required
- key_references

verdicts:
- severity -> adjustment_reason
- severity -> adjusted_severity
- impact -> worst_case
- remediation -> detail
- remediation -> workaround
- remediation -> effort
- verdict
- priority
- confidence
- rationale
- data_gaps
- exploitability -> likelihood(?)

drop copied fields:
- weakness -> mechanism
