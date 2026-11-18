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
- `rationale` [world] legacy  → category: 
- `severity.adjustment_reason` [context] rarely  → category: 

## 20261118-113709 CVE-2007-6703 [e9907e]
declared background_knowledge: 1 item(s)
- `impact.worst_case` [name] Windows  → category: 
- `rationale` [context] internet-facing  → category: 

## 20261118-113709 CVE-2026-70613 [7bbd9c]
- `rationale` [name] CWEs  → category: 

## 20261118-113709 CVE-2026-86509 [06d1a3]
declared background_knowledge: 1 item(s)
- `severity.adjustment_reason` [name] LAN-side  → category: 
- `severity.adjustment_reason` [world] consumer router  → category: 
- `summary` [world] embedded  → category: 

## 20261118-113709 CVE-2026-79577 [de1b82]
declared background_knowledge: 1 item(s)
- `impact.worst_case` [name] SSO-protected  → category: 

## 20261118-113709 CVE-2007-6252 [c75d2b]
declared background_knowledge: 1 item(s)
- `rationale` [world] legacy  → category: 
- `remediation.workaround` [name] Explorer  → category: 
- `remediation.workaround` [name] Internet  → category: 
- `summary` [name] Explorer  → category: 
- `summary` [name] Internet  → category: 
- `summary` [name] Windows  → category: 

## 20261118-113709 CVE-2024-28224 [ad3154]
declared background_knowledge: 1 item(s)
- `remediation.workaround` [name] Host/Origin  → category: 

## 20261118-113709 CVE-2008-1112 [cd7d27]
- `rationale` [name] MITRE-rejected  → category: 

## 20261118-113709 CVE-2002-1774 [e67baa]
declared background_knowledge: 1 item(s)
- `remediation.detail` [name] AutoProtect/on-access  → category: 

## 20261118-113709 CVE-2024-28088 [5e391a]
declared background_knowledge: 1 item(s)
- `rationale` [context] widely  → category: 
- `rationale` [name] Python  → category: 
- `rationale` [world] embedded  → category: 
- `summary` [name] LangChain's  → category: 

## 20261118-113709 CVE-2026-20963 [4fb3c9]
declared background_knowledge: 2 item(s)
- `rationale` [context] internet-facing  → category: 
- `remediation.detail` [name] Edition  → category: 
- `summary` [world] actively exploited  → category: 
- `summary` [world] in the wild  → category: 

## 20261118-113709 CVE-2020-1631 [dbea2e]
declared background_knowledge: 1 item(s)
- `severity.adjustment_reason` [context] internet-facing  → category: 
