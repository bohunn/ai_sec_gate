# Prose-audit candidates (automatic pre-screen of run 20261118-135633, blind to arm)

Provenance, not truth: each line is a phrase found in a prose field but **not in the input the
model saw** (`app input <CVE>`). The pre-screen is deliberately wide. Assign each line one letter
after `→ category:` (A memory, B paraphrase, C generic, D inference, E deployment assumption;
VALIDATION.md, "Prose audit"). Add a line in the same format for an A or E claim the pre-screen
missed, with a note `(added: ...)`. Mark doubt as `A?` or `A/D`.

The arm is hidden behind a per-section token; the map is in `.arms-20261118-schema2.json`.
Do not open it before the last letter is in. The output file for a section is
`data/runs/<run>/raw/run1/<arm>-<CVE>.json`; `scripts/prose-worksheet.py` renders input and
output side by side without revealing the arm.

## 20261118-135633 CVE-2026-79379 [fd534e]
declared background_knowledge: 1 item(s)
- `rationale` [context] usually  → category: E  (undeclared: the declared item is about the SBC codec)

## 20261118-135633 CVE-2002-1774 [62e400]
declared background_knowledge: 1 item(s)
- `remediation.detail` [name] AutoProtect/on-access  → category: B

## 20261118-135633 CVE-2024-28088 [731187]
declared background_knowledge: 1 item(s)
- `summary` [name] LangChain's  → category: B

## 20261118-135633 CVE-2008-1146 [28e9cc]
declared background_knowledge: 1 item(s)
- `remediation.workaround` [name] DNSSEC-validating  → category: C
- `severity.adjustment_reason` [world] long out of support  → category: A  (added: declared)
- `severity.adjustment_reason` [context] essentially absent from current deployments  → category: E  (added: undeclared; the declared item covers support dates, not deployment)
- `remediation.detail` [world] a currently supported OpenBSD release that replaced the X3 PRNG  → category: A  (added: undeclared; claim about later OpenBSD releases)
- `rationale` [date] from 2000-2007  → category: A  (added: declared)

## 20261118-135633 CVE-2026-86509 [3971d3]
declared background_knowledge: 1 item(s)
- `impact.worst_case` [name] Wi-Fi  → category: A  (declared; states as fact that the device has Wi-Fi)
- `remediation.workaround` [name] LAN/Wi-Fi  → category: C
- `severity.adjustment_reason` [context] network gateway  → category: E  (added: declared)

## 20261118-135633 CVE-2020-1631 [3f0b7b]
declared background_knowledge: 1 item(s)
- `rationale` [context] internet-facing  → category: E  (declared)
- `severity.adjustment_reason` [context] network-edge devices  → category: E  (added: declared)

## 20261118-135633 CVE-2008-1113 [3910d6]
declared background_knowledge: 1 item(s)
- `summary` [name] RADIUS/authentication  → category: A  (undeclared: the record says PEAP and server certificates, not RADIUS)

## 20261118-135633 CVE-2026-79577 [550d8d]
declared background_knowledge: 1 item(s)
- `impact.worst_case` [name] SSO-protected  → category: D

## 20261118-135633 CVE-2024-36423 [29904b]
- `remediation.workaround` [name] HTML-bearing  → category: C

## 20261118-135633 CVE-2026-20963 [faee2a]
declared background_knowledge: 1 item(s)
- `rationale` [name] Edition  → category: B
- `remediation.detail` [name] Edition  → category: B
- `severity.adjustment_reason` [world] actively exploited  → category: B
- `summary` [name] CISA's  → category: B
- `summary` [world] in the wild  → category: B

## 20261118-135633 CVE-2007-6252 [045cf6]
declared background_knowledge: 2 item(s)
- `remediation.detail` [name] Explorer  → category: A  (declared)
- `remediation.detail` [name] Internet  → category: A  (declared)
- `summary` [name] Explorer  → category: A  (declared)
- `summary` [name] Internet  → category: A  (declared)
- `summary` [name] Windows  → category: A  (declared)
- `summary` [world] legacy  → category: D
- `rationale` [world] long-abandoned  → category: A  (added: declared)
- `rationale` [context] practical exposure for a modern build pipeline is minimal  → category: E  (added: declared)

## 20261118-135633 CVE-2008-1115 [a94314]
declared background_knowledge: 1 item(s)
- `severity.adjustment_reason` [context] in practice  → category: D

## 20261118-135633 CVE-2001-1533 [531399]
declared background_knowledge: 1 item(s)
- `remediation.detail` [name] DDoS  → category: C
- `remediation.detail` [world] unsupported  → category: A  (declared)

## 20261118-135633 CVE-2026-24061 [876e1b]
declared background_knowledge: 1 item(s)
- `rationale` [world] actively exploited  → category: B
- `summary` [name] CISA's  → category: B
- `summary` [name] Vulnerabilities  → category: B
- `summary` [world] cisa  → category: B
- `summary` [world] passed through to login as a command-line option  → category: A  (added: undeclared; the record does not mention login)
