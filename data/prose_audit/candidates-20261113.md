# Prose-audit candidates (automatic pre-screen, 2026-11-13)

Provenance, not truth: each line is a phrase found in a prose field but **not in the input the model saw**.
The pre-screen is deliberately wide. A human assigns each line one of five categories (VALIDATION.md,
"Prose audit"):

- **A memory** - a fact about the world the record does not contain ("DIR-895L is end-of-life").
- **B paraphrase** - restates something that is in the input.
- **C generic** - triage language that asserts nothing about this CVE.
- **D inference** - follows from the input alone; test: would a reader with only the input and no
  knowledge of the world reach it? (published 2001 → "old": yes; "DIR-895L" → EOL: no).
- **E deployment assumption** - a claim about how the component is deployed ("internet-exposed",
  "commonly") that neither the record nor training data can supply. Touches the verdict directly.

Only A and E count toward the metric; they are reported separately. Keep the run × arm split.
Both runs are `claude-opus-5` (run 20260928-093807 settled against the API usage record, see its
`PROVENANCE.md`), so a difference between runs is run-to-run variance of one model.

| run | arm | outputs | with ≥1 candidate |
|---|---|---|---|
| 20260919-000440 | native | 26 | 18 |
| 20260919-000440 | prompt | 25 | 14 |
| 20260928-093807 | native | 26 | 14 |
| 20260928-093807 | prompt | 26 | 13 |

Candidate lines by pre-screen kind (not yet adjudicated): context 22, name 82, world 32

Kinds: `world` = needs world knowledge (A or D after adjudication); `context` = deployment assumption (E or C);
`date`, `name` = specific tokens absent from the input (any category).

## 20260919-000440 native CVE-2002-1774
- `rationale` [world] unsupported  → category: 
- `remediation.detail` [name] AutoProtect/on-access  → category: 
- `severity.adjustment_reason` [world] legacy  → category: 

## 20260919-000440 native CVE-2007-6252
- `rationale` [name] Explorer  → category: 
- `rationale` [name] Internet  → category: 
- `rationale` [world] legacy  → category: 
- `remediation.workaround` [name] Explorer  → category: 
- `remediation.workaround` [name] Internet  → category: 
- `severity.adjustment_reason` [world] legacy  → category: 
- `summary` [name] Explorer  → category: 
- `summary` [name] Internet  → category: 

## 20260919-000440 native CVE-2007-6703
- `impact.worst_case` [name] Mobile  → category: 
- `impact.worst_case` [name] Windows  → category: 
- `rationale` [world] legacy  → category: 
- `severity.adjustment_reason` [world] legacy  → category: 

## 20260919-000440 native CVE-2008-1115
- `remediation.detail` [world] end-of-life  → category: 

## 20260919-000440 native CVE-2008-1146
- `rationale` [name] OS-upgrade  → category: 
- `rationale` [world] end-of-life  → category: 

## 20260919-000440 native CVE-2024-12366
- `remediation.detail` [name] PandasAI's  → category: 

## 20260919-000440 native CVE-2024-28088
- `summary` [name] LangChain's  → category: 

## 20260919-000440 native CVE-2024-28224
- `remediation.workaround` [name] Host  → category: 
- `summary` [name] Host/origin  → category: 

## 20260919-000440 native CVE-2024-31224
- `severity.adjustment_reason` [context] internet-exposed  → category: 
- `severity.adjustment_reason` [name] Internet-exposed  → category: 

## 20260919-000440 native CVE-2024-36422
- `remediation.workaround` [name] WAF/reverse  → category: 

## 20260919-000440 native CVE-2024-36423
- `remediation.workaround` [name] IDs  → category: 

## 20260919-000440 native CVE-2026-20963
- `remediation.detail` [name] Edition  → category: 
- `severity.adjustment_reason` [context] commonly  → category: 
- `severity.adjustment_reason` [context] internet-exposed  → category: 

## 20260919-000440 native CVE-2026-24061
- `severity.adjustment_reason` [context] rarely  → category: 

## 20260919-000440 native CVE-2026-46251
- `rationale` [context] rarely  → category: 
- `summary` [context] in practice  → category: 

## 20260919-000440 native CVE-2026-79379
- `rationale` [world] embedded  → category: 
- `remediation.detail` [context] usually  → category: 
- `remediation.detail` [name] ODM/vendor  → category: 
- `remediation.detail` [name] SoCs  → category: 
- `remediation.detail` [world] embedded  → category: 

## 20260919-000440 native CVE-2026-79577
- `impact.worst_case` [name] SSO-protected  → category: 

## 20260919-000440 native CVE-2026-82710
- `severity.adjustment_reason` [context] in practice  → category: 

## 20260919-000440 native CVE-2026-86509
- `remediation.detail` [world] end-of-life  → category: 
- `remediation.workaround` [name] Wi-Fi  → category: 
- `severity.adjustment_reason` [world] consumer router  → category: 
- `severity.adjustment_reason` [world] legacy  → category: 

## 20260919-000440 prompt CVE-2007-6252
- `rationale` [world] legacy  → category: 
- `remediation.workaround` [name] Explorer  → category: 
- `remediation.workaround` [name] Internet  → category: 
- `severity.adjustment_reason` [context] typically  → category: 
- `summary` [context] typically  → category: 
- `summary` [name] Windows  → category: 

## 20260919-000440 prompt CVE-2007-6703
- `impact.worst_case` [name] Mobile  → category: 
- `impact.worst_case` [name] Windows  → category: 

## 20260919-000440 prompt CVE-2008-1115
- `remediation.detail` [name] Sun/Oracle  → category: 
- `severity.adjustment_reason` [context] rarely  → category: 
- `severity.adjustment_reason` [world] end-of-life  → category: 

## 20260919-000440 prompt CVE-2020-1631
- `rationale` [name] CISA's  → category: 

## 20260919-000440 prompt CVE-2024-12366
- `remediation.workaround` [name] PandasAI's  → category: 
- `summary` [name] PandasAI's  → category: 

## 20260919-000440 prompt CVE-2024-28088
- `summary` [name] LangChain's  → category: 

## 20260919-000440 prompt CVE-2024-31224
- `summary` [context] internet-exposed  → category: 

## 20260919-000440 prompt CVE-2026-20963
- `rationale` [name] Edition  → category: 
- `remediation.detail` [name] Edition  → category: 
- `severity.adjustment_reason` [context] widely  → category: 

## 20260919-000440 prompt CVE-2026-46251
- `rationale` [context] typical deployment  → category: 

## 20260919-000440 prompt CVE-2026-70613
- `rationale` [name] CWEs  → category: 

## 20260919-000440 prompt CVE-2026-79379
- `remediation.detail` [name] ODM/vendor  → category: 

## 20260919-000440 prompt CVE-2026-79577
- `impact.worst_case` [name] SSO-protected  → category: 

## 20260919-000440 prompt CVE-2026-84282
- `impact.worst_case` [name] URLs  → category: 
- `rationale` [context] typical deployment  → category: 

## 20260919-000440 prompt CVE-2026-86509
- `rationale` [world] embedded  → category: 
- `remediation.workaround` [name] LAN/Wi-Fi  → category: 

## 20260928-093807 native CVE-2001-1533
- `rationale` [world] end-of-life  → category: 
- `rationale` [world] legacy  → category: 

## 20260928-093807 native CVE-2002-1774
- `rationale` [world] legacy  → category: 
- `remediation.detail` [name] AutoProtect/on-access  → category: 
- `severity.adjustment_reason` [world] end-of-life  → category: 

## 20260928-093807 native CVE-2007-6252
- `rationale` [name] Explorer  → category: 
- `rationale` [name] Internet  → category: 
- `remediation.workaround` [name] Explorer  → category: 
- `remediation.workaround` [name] Internet  → category: 
- `severity.adjustment_reason` [name] Explorer  → category: 
- `severity.adjustment_reason` [name] Internet  → category: 
- `severity.adjustment_reason` [world] legacy  → category: 
- `summary` [name] Explorer  → category: 
- `summary` [name] Internet  → category: 
- `summary` [name] Windows  → category: 

## 20260928-093807 native CVE-2007-6703
- `rationale` [world] legacy  → category: 
- `summary` [name] Mobile/CE  → category: 
- `summary` [name] Windows  → category: 

## 20260928-093807 native CVE-2008-1113
- `remediation.detail` [name] Cisco's  → category: 
- `remediation.workaround` [name] APs  → category: 

## 20260928-093807 native CVE-2008-1115
- `rationale` [world] legacy  → category: 

## 20260928-093807 native CVE-2020-1631
- `rationale` [context] widely  → category: 

## 20260928-093807 native CVE-2024-12366
- `severity.adjustment_reason` [name] LLM-mediated  → category: 

## 20260928-093807 native CVE-2024-28088
- `summary` [name] LangChain's  → category: 

## 20260928-093807 native CVE-2024-28224
- `remediation.workaround` [name] Host/Origin  → category: 
- `severity.adjustment_reason` [name] NVD's  → category: 
- `summary` [name] Host/Origin  → category: 

## 20260928-093807 native CVE-2026-20963
- `remediation.detail` [name] Edition  → category: 
- `remediation.workaround` [context] internet-facing  → category: 
- `severity.adjustment_reason` [context] widely  → category: 

## 20260928-093807 native CVE-2026-70613
- `rationale` [name] CNA's  → category: 

## 20260928-093807 native CVE-2026-79379
- `remediation.detail` [name] ODM/vendor  → category: 

## 20260928-093807 native CVE-2026-86509
- `remediation.detail` [world] end-of-life  → category: 
- `remediation.workaround` [name] VLAN/Wi-Fi  → category: 
- `severity.adjustment_reason` [world] consumer router  → category: 
- `severity.adjustment_reason` [world] end-of-life  → category: 

## 20260928-093807 prompt CVE-2001-1533
- `rationale` [world] end-of-life  → category: 
- `rationale` [world] legacy  → category: 
- `remediation.workaround` [name] DDoS  → category: 

## 20260928-093807 prompt CVE-2002-1774
- `rationale` [world] legacy  → category: 
- `severity.adjustment_reason` [world] legacy  → category: 

## 20260928-093807 prompt CVE-2007-6252
- `rationale` [name] Explorer  → category: 
- `rationale` [name] Internet  → category: 
- `rationale` [world] legacy  → category: 
- `remediation.workaround` [name] Explorer  → category: 
- `remediation.workaround` [name] Internet  → category: 
- `severity.adjustment_reason` [name] Explorer  → category: 
- `severity.adjustment_reason` [name] Internet  → category: 
- `summary` [name] Explorer  → category: 
- `summary` [name] Internet  → category: 
- `summary` [name] Windows  → category: 

## 20260928-093807 prompt CVE-2007-6703
- `rationale` [context] rarely  → category: 
- `summary` [name] Mobile/PocketPC  → category: 
- `summary` [name] Windows  → category: 

## 20260928-093807 prompt CVE-2008-1113
- `remediation.detail` [name] Cisco/Secunia  → category: 

## 20260928-093807 prompt CVE-2008-1146
- `rationale` [world] unsupported  → category: 

## 20260928-093807 prompt CVE-2020-1631
- `rationale` [name] CISA's  → category: 
- `summary` [name] CISA's  → category: 

## 20260928-093807 prompt CVE-2024-12366
- `summary` [name] PandasAI's  → category: 

## 20260928-093807 prompt CVE-2024-28088
- `summary` [name] LangChain's  → category: 

## 20260928-093807 prompt CVE-2024-31224
- `severity.adjustment_reason` [context] internet-exposed  → category: 

## 20260928-093807 prompt CVE-2026-20963
- `remediation.detail` [name] Edition  → category: 
- `severity.adjustment_reason` [context] commonly  → category: 
- `severity.adjustment_reason` [context] internet-exposed  → category: 

## 20260928-093807 prompt CVE-2026-70613
- `rationale` [name] CWEs  → category: 

## 20260928-093807 prompt CVE-2026-84282
- `impact.worst_case` [name] URLs  → category: 

