# Prose-audit candidates (automatic pre-screen of run 20261117-233510, blind to arm)

Provenance, not truth: each line is a phrase found in a prose field but **not in the input the
model saw** (`app input <CVE>`). The pre-screen is deliberately wide. Assign each line one letter
after `→ category:` (A memory, B paraphrase, C generic, D inference, E deployment assumption;
VALIDATION.md, "Prose audit"). Add a line in the same format for an A or E claim the pre-screen
missed, with a note `(added: ...)`. Mark doubt as `A?` or `A/D`.

The arm is hidden behind a per-section token; the map is in `.arms-20261118.json`.
Do not open it before the last letter is in. The output file for a section is
`data/runs/<run>/raw/run1/<arm>-<CVE>.json`; `scripts/prose-worksheet.py` renders input and
output side by side without revealing the arm.

## 20261117-233510 CVE-2024-12366 [bae28e]
- `summary` [name] PandasAI's  → category: B

## 20261117-233510 CVE-2026-79379 [452103]
- `severity.adjustment_reason` [name] Bluetooth-range  → category: B

## 20261117-233510 CVE-2001-1533 [95e627]
- `rationale` [world] end-of-life  → category: A
- `remediation.detail` [world] long out of support  → category: A  (added: vendor support status is not in the record)

## 20261117-233510 CVE-2026-24061 [7ce042]
- `rationale` [name] KEV-listed  → category: B
- `rationale` [world] actively exploited  → category: B
- `summary` [name] CISA's  → category: B
- `summary` [name] Vulnerabilities  → category: B
- `summary` [world] cisa  → category: B

## 20261117-233510 CVE-2024-12366 [090001]
- `summary` [name] PandasAI's  → category: B

## 20261117-233510 CVE-2001-1533 [cd7efa]
- `rationale` [world] legacy  → category: D
- `remediation.detail` [world] end-of-life  → category: A

## 20261117-233510 CVE-2024-28088 [4f294b]
- `summary` [name] LangChain's  → category: B

## 20261117-233510 CVE-2024-36423 [f25713]
- `remediation.workaround` [name] HTML-bearing  → category: C

## 20261117-233510 CVE-2007-6703 [9b599d]
- `impact.worst_case` [name] Mobile  → category: A
- `impact.worst_case` [name] Windows  → category: A
- `rationale` [context] rarely  → category: E

## 20261117-233510 CVE-2024-28088 [fd77b5]
- `summary` [name] LangChain's  → category: B

## 20261117-233510 CVE-2008-1115 [d8c4fa]
- `severity.adjustment_reason` [context] most deployments  → category: E
- `severity.adjustment_reason` [world] end-of-life  → category: A
- `rationale` [world] long out of support  → category: A  (added: vendor support status is not in the record)

## 20261117-233510 CVE-2026-24061 [333016]
- `summary` [world] in the wild  → category: B

## 20261117-233510 CVE-2026-46251 [be0e9a]
- `rationale` [context] typical deployment  → category: E
- `rationale` [world] kev  → category: B
- `summary` [world] experimental  → category: A  (added: the record never calls EXTENT_TREE_V2 experimental)
- `severity.adjustment_reason` [world] experimental  → category: A  (added: the record never calls EXTENT_TREE_V2 experimental)
- `remediation.workaround` [world] experimental  → category: A  (added: the record never calls EXTENT_TREE_V2 experimental)
- `rationale` [world] experimental  → category: A  (added: the record never calls EXTENT_TREE_V2 experimental)

## 20261117-233510 CVE-2002-1774 [f8526b]
- `rationale` [world] kev  → category: B
- `remediation.detail` [name] AutoProtect/on-access  → category: B  (legend example; the same phrase is A on one line of candidates-20261113.md and B on the other, still unresolved)

## 20261117-233510 CVE-2024-31224 [c5822d]
- `summary` [context] internet-exposed  → category: B

## 20261117-233510 CVE-2007-6252 [95617f]
- `rationale` [world] legacy  → category: D
- `remediation.detail` [name] CLSIDs  → category: A/C  (kill-bit advice is generic, but it asserts what the US-CERT note contains)
- `remediation.workaround` [name] Explorer  → category: A
- `remediation.workaround` [name] Internet  → category: A
- `severity.adjustment_reason` [world] legacy  → category: D
- `summary` [name] Explorer  → category: A
- `summary` [name] Internet  → category: A
- `rationale` [context] unlikely to be present in modern build dependencies  → category: E  (added: the legend example)

## 20261117-233510 CVE-2024-31224 [bbdfbc]
- `severity.adjustment_reason` [context] internet-exposed  → category: B

## 20261117-233510 CVE-2026-20963 [7ffca4]
- `rationale` [world] in the wild  → category: B
- `remediation.detail` [name] Edition  → category: B
- `severity.adjustment_reason` [context] widely  → category: E
- `summary` [name] CISA's  → category: B
- `summary` [world] actively exploited  → category: B

## 20261117-233510 CVE-2007-6703 [791ab7]
- `summary` [name] ActiveSync-style  → category: A

## 20261117-233510 CVE-2007-6252 [d58ebd]
- `severity.adjustment_reason` [world] legacy  → category: D
- `summary` [name] Windows  → category: A
- `rationale` [context] practical likelihood in a modern deployment is low  → category: E  (added: deployment claim)

## 20261117-233510 CVE-2026-86509 [e96c5f]
- `remediation.workaround` [name] LAN/Wi-Fi  → category: C

## 20261117-233510 CVE-2002-1774 [e5aaf7]
- `rationale` [world] unsupported  → category: A
- `remediation.detail` [world] end-of-life  → category: A
- `severity.adjustment_reason` [context] unlikely to appear in a build pipeline  → category: E  (added: the legend example)

## 20261117-233510 CVE-2026-86509 [3fb927]
- `remediation.detail` [world] end-of-life  → category: A?  (conditional "if the model is end-of-life"; same call as in candidates-20261113.md)
- `severity.adjustment_reason` [context] internet-facing  → category: C  (a comparison, not a claim that this device is internet-facing)

## 20261117-233510 CVE-2026-20963 [a66c20]
- `rationale` [name] Edition  → category: B
- `remediation.detail` [name] Edition  → category: B
- `severity.adjustment_reason` [world] actively exploited  → category: B
- `summary` [name] CISA's  → category: B
- `summary` [world] in the wild  → category: B

## 20261117-233510 CVE-2008-1146 [d32ed9]
- `remediation.workaround` [name] DNSSEC-validating/0x20-randomizing  → category: C
- `remediation.detail` [world] a current OpenBSD release whose resolver uses a cryptographically strong transaction-ID source  → category: A  (added: claim about current OpenBSD, not in the record)
- `rationale` [date] from 2000-2007  → category: A  (added: release years of OpenBSD 2.8-4.2 are not in the record)
- `rationale` [context] almost certainly noise in a modern dependency graph  → category: E  (added: deployment claim)

## 20261117-233510 CVE-2024-28224 [2e15c8]
- `remediation.workaround` [name] Host/Origin  → category: C
- `summary` [world] does not validate the request origin  → category: A  (added: the record says only "DNS rebinding"; same call as Host/origin in candidates-20261113.md)
