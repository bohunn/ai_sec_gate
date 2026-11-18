# Prose-audit candidates (automatic pre-screen of run 20261118-113709, blind to arm)

Provenance, not truth: each line is a phrase found in a prose field but **not in the input the
model saw** (`app input <CVE>`). The pre-screen is deliberately wide. Assign each line one letter
after `→ category:` (A memory, B paraphrase, C generic, D inference, E deployment assumption;
VALIDATION.md, "Prose audit"). Add a line in the same format for an A or E claim the pre-screen
missed, with a note `(added: ...)`. Mark doubt as `A?` or `A/D`.

The arm is hidden behind a per-section token; the map is in `.arms-20261118-schema.json`.
Do not open it before the last letter is in. The output file for a section is
`data/runs/<run>/raw/run1/<arm>-<CVE>.json`; `scripts/prose-worksheet.py` renders input and
output side by side without revealing the arm.

## 20261118-113709 CVE-2008-1115 [da2773]
declared background_knowledge: 1 item(s)
- `rationale` [world] legacy  → category: D
- `severity.adjustment_reason` [context] rarely  → category: E  (undeclared: the declared item covers lifecycle, not build pipelines)

## 20261118-113709 CVE-2007-6703 [e9907e]
declared background_knowledge: 1 item(s)
- `impact.worst_case` [name] Windows  → category: A  (declared)
- `rationale` [context] internet-facing  → category: E  (declared)
- `remediation.workaround` [context] normally only needed for local device synchronisation  → category: E  (added: declared)

## 20261118-113709 CVE-2026-70613 [7bbd9c]
- `rationale` [name] CWEs  → category: B

## 20261118-113709 CVE-2026-86509 [06d1a3]
declared background_knowledge: 1 item(s)
- `severity.adjustment_reason` [name] LAN-side  → category: D
- `severity.adjustment_reason` [world] consumer router  → category: A  (declared)
- `summary` [world] embedded  → category: D  ("embedded DHCP server": the record names udhcpcd as a component of the device)

## 20261118-113709 CVE-2026-79577 [de1b82]
declared background_knowledge: 1 item(s)
- `impact.worst_case` [name] SSO-protected  → category: D

## 20261118-113709 CVE-2007-6252 [c75d2b]
declared background_knowledge: 1 item(s)
- `rationale` [world] legacy  → category: D
- `remediation.workaround` [name] Explorer  → category: A  (declared)
- `remediation.workaround` [name] Internet  → category: A  (declared)
- `summary` [name] Explorer  → category: A  (declared)
- `summary` [name] Internet  → category: A  (declared)
- `summary` [name] Windows  → category: A  (declared)
- `rationale` [context] unlikely to appear in modern builds  → category: E  (added: undeclared; the legend example)

## 20261118-113709 CVE-2024-28224 [ad3154]
declared background_knowledge: 1 item(s)
- `remediation.workaround` [name] Host/Origin  → category: C
- `summary` [world] without validating the request origin/host  → category: A  (added: undeclared; the record says only "DNS rebinding")
- `severity.adjustment_reason` [world] normally bound to loopback  → category: A  (added: declared; product default is not in the record)

## 20261118-113709 CVE-2008-1112 [cd7d27]
- `rationale` [name] MITRE-rejected  → category: A  (undeclared, empty outlet: the record does not name MITRE)
- `summary` [world] rejected by MITRE  → category: A  (added: undeclared, empty outlet; same claim as the rationale line)

## 20261118-113709 CVE-2002-1774 [e67baa]
declared background_knowledge: 1 item(s)
- `remediation.detail` [name] AutoProtect/on-access  → category: B
- `severity.adjustment_reason` [context] unlikely to appear in a build dependency graph  → category: E  (added: declared; the legend example)

## 20261118-113709 CVE-2024-28088 [5e391a]
declared background_knowledge: 1 item(s)
- `rationale` [context] widely  → category: E  (declared)
- `rationale` [name] Python  → category: A  (declared)
- `rationale` [world] embedded  → category: E  (declared; same claim as "widely")
- `summary` [name] LangChain's  → category: B

## 20261118-113709 CVE-2026-20963 [4fb3c9]
declared background_knowledge: 2 item(s)
- `rationale` [context] internet-facing  → category: E  (declared)
- `remediation.detail` [name] Edition  → category: B
- `summary` [world] actively exploited  → category: B
- `summary` [world] in the wild  → category: B

## 20261118-113709 CVE-2020-1631 [dbea2e]
declared background_knowledge: 1 item(s)
- `severity.adjustment_reason` [context] internet-facing  → category: E  (declared)
