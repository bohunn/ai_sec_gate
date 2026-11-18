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
- `rationale` [world] unsupported  → category: A
- `remediation.detail` [name] AutoProtect/on-access  → category: A
- `severity.adjustment_reason` [world] legacy  → category: D
- `severity.adjustment_reason` [context] unlikely to be present in a modern build  → category: E  (added: missed by the pre-screen)

## 20260919-000440 native CVE-2007-6252
- `rationale` [name] Explorer  → category: A
- `rationale` [name] Internet  → category: A
- `rationale` [world] legacy  → category: D
- `remediation.workaround` [name] Explorer  → category: A
- `remediation.workaround` [name] Internet  → category: A
- `severity.adjustment_reason` [world] legacy  → category: D
- `summary` [name] Explorer  → category: A
- `summary` [name] Internet  → category: A

## 20260919-000440 native CVE-2007-6703
- `impact.worst_case` [name] Mobile  → category: A
- `impact.worst_case` [name] Windows  → category: A
- `rationale` [world] legacy  → category: D
- `severity.adjustment_reason` [world] legacy  → category: D

## 20260919-000440 native CVE-2008-1115
- `remediation.detail` [world] end-of-life  → category: A
- `rationale` [world] long out of support  → category: A  (added: missed by the pre-screen)

## 20260919-000440 native CVE-2008-1146
- `rationale` [name] OS-upgrade  → category: D
- `rationale` [world] end-of-life  → category: A

## 20260919-000440 native CVE-2024-12366
- `remediation.detail` [name] PandasAI's  → category: B

## 20260919-000440 native CVE-2024-28088
- `summary` [name] LangChain's  → category: B

## 20260919-000440 native CVE-2024-28224
- `remediation.workaround` [name] Host  → category: C
- `summary` [name] Host/origin  → category: A

## 20260919-000440 native CVE-2024-31224
- `severity.adjustment_reason` [context] internet-exposed  → category: B
- `severity.adjustment_reason` [name] Internet-exposed  → category: B

## 20260919-000440 native CVE-2024-36422
- `remediation.workaround` [name] WAF/reverse  → category: C

## 20260919-000440 native CVE-2024-36423
- `remediation.workaround` [name] IDs  → category: B

## 20260919-000440 native CVE-2026-20963
- `remediation.detail` [name] Edition  → category: B
- `severity.adjustment_reason` [context] commonly  → category: E
- `severity.adjustment_reason` [context] internet-exposed  → category: E

## 20260919-000440 native CVE-2026-24061
- `severity.adjustment_reason` [context] rarely  → category: E

## 20260919-000440 native CVE-2026-46251
- `rationale` [context] rarely  → category: E
- `summary` [context] in practice  → category: B
- `summary` [world] experimental  → category: A  (added: missed by the pre-screen)
- `severity.adjustment_reason` [world] experimental, non-default  → category: A  (added: missed by the pre-screen)
- `remediation.workaround` [world] experimental  → category: A  (added: missed by the pre-screen)
- `rationale` [world] experimental  → category: A  (added: missed by the pre-screen)

## 20260919-000440 native CVE-2026-79379
- `rationale` [world] embedded  → category: D
- `remediation.detail` [context] usually  → category: A
- `remediation.detail` [name] ODM/vendor  → category: C
- `remediation.detail` [name] SoCs  → category: B
- `remediation.detail` [world] embedded  → category: D

## 20260919-000440 native CVE-2026-79577
- `impact.worst_case` [name] SSO-protected  → category: D

## 20260919-000440 native CVE-2026-82710
- `severity.adjustment_reason` [context] in practice  → category: D

## 20260919-000440 native CVE-2026-86509
- `remediation.detail` [world] end-of-life  → category: A?  (conditional "if it is end-of-life"; reference case, seen before adjudication)
- `remediation.workaround` [name] Wi-Fi  → category: C
- `severity.adjustment_reason` [world] consumer router  → category: A  (reference case, seen before adjudication)
- `severity.adjustment_reason` [world] legacy  → category: A  (published 2026, so not from the date; reference case, seen before adjudication)

## 20260919-000440 prompt CVE-2007-6252
- `rationale` [world] legacy  → category: D
- `remediation.workaround` [name] Explorer  → category: A
- `remediation.workaround` [name] Internet  → category: A
- `severity.adjustment_reason` [context] typically  → category: A
- `summary` [context] typically  → category: A
- `summary` [name] Windows  → category: A

## 20260919-000440 prompt CVE-2007-6703
- `impact.worst_case` [name] Mobile  → category: A
- `impact.worst_case` [name] Windows  → category: A

## 20260919-000440 prompt CVE-2008-1115
- `remediation.detail` [name] Sun/Oracle  → category: A
- `severity.adjustment_reason` [context] rarely  → category: E
- `severity.adjustment_reason` [world] end-of-life  → category: A

## 20260919-000440 prompt CVE-2020-1631
- `rationale` [name] CISA's  → category: B

## 20260919-000440 prompt CVE-2024-12366
- `remediation.workaround` [name] PandasAI's  → category: B
- `summary` [name] PandasAI's  → category: B

## 20260919-000440 prompt CVE-2024-28088
- `summary` [name] LangChain's  → category: B

## 20260919-000440 prompt CVE-2024-31224
- `summary` [context] internet-exposed  → category: B

## 20260919-000440 prompt CVE-2026-20963
- `rationale` [name] Edition  → category: B
- `remediation.detail` [name] Edition  → category: B
- `severity.adjustment_reason` [context] widely  → category: E

## 20260919-000440 prompt CVE-2026-46251
- `rationale` [context] typical deployment  → category: E
- `summary` [world] experimental  → category: A  (added: missed by the pre-screen)
- `severity.adjustment_reason` [world] experimental  → category: A  (added: missed by the pre-screen)
- `severity.adjustment_reason` [context] not enabled in normal deployments  → category: E  (added: missed by the pre-screen)
- `remediation.workaround` [world] experimental  → category: A  (added: missed by the pre-screen)
- `rationale` [world] experimental  → category: A  (added: missed by the pre-screen)

## 20260919-000440 prompt CVE-2026-70613
- `rationale` [name] CWEs  → category: B

## 20260919-000440 prompt CVE-2026-79379
- `remediation.detail` [name] ODM/vendor  → category: C

## 20260919-000440 prompt CVE-2026-79577
- `impact.worst_case` [name] SSO-protected  → category: D

## 20260919-000440 prompt CVE-2026-84282
- `impact.worst_case` [name] URLs  → category: B
- `rationale` [context] typical deployment  → category: E

## 20260919-000440 prompt CVE-2026-86509
- `rationale` [world] embedded  → category: A  ("embedded router": the record never says what a DIR-895L is)
- `remediation.workaround` [name] LAN/Wi-Fi  → category: C

## 20260928-093807 native CVE-2001-1533
- `rationale` [world] end-of-life  → category: A
- `rationale` [world] legacy  → category: D
- `remediation.detail` [world] long out of support  → category: A  (added: missed by the pre-screen)

## 20260928-093807 native CVE-2002-1774
- `rationale` [world] legacy  → category: D
- `remediation.detail` [name] AutoProtect/on-access  → category: B
- `severity.adjustment_reason` [world] end-of-life  → category: A
- `severity.adjustment_reason` [context] unlikely to be a build dependency  → category: E  (added: missed by the pre-screen)

## 20260928-093807 native CVE-2007-6252
- `rationale` [name] Explorer  → category: A
- `rationale` [name] Internet  → category: A
- `remediation.workaround` [name] Explorer  → category: A
- `remediation.workaround` [name] Internet  → category: A
- `severity.adjustment_reason` [name] Explorer  → category: A
- `severity.adjustment_reason` [name] Internet  → category: A
- `severity.adjustment_reason` [world] legacy  → category: D
- `summary` [name] Explorer  → category: A
- `summary` [name] Internet  → category: A
- `summary` [name] Windows  → category: A
- `rationale` [context] exposure for modern software supply chains is negligible  → category: E  (added: missed by the pre-screen)

## 20260928-093807 native CVE-2007-6703
- `rationale` [world] legacy  → category: D
- `summary` [name] Mobile/CE  → category: A
- `summary` [name] Windows  → category: A

## 20260928-093807 native CVE-2008-1113
- `remediation.detail` [name] Cisco's  → category: D
- `remediation.workaround` [name] APs  → category: B

## 20260928-093807 native CVE-2008-1115
- `rationale` [world] legacy  → category: D
- `remediation.detail` [world] long out of support  → category: A  (added: missed by the pre-screen)

## 20260928-093807 native CVE-2020-1631
- `rationale` [context] widely  → category: E
- `severity.adjustment_reason` [context] edge network device  → category: E  (added: missed by the pre-screen)

## 20260928-093807 native CVE-2024-12366
- `severity.adjustment_reason` [name] LLM-mediated  → category: B

## 20260928-093807 native CVE-2024-28088
- `summary` [name] LangChain's  → category: B

## 20260928-093807 native CVE-2024-28224
- `remediation.workaround` [name] Host/Origin  → category: C
- `severity.adjustment_reason` [name] NVD's  → category: B
- `summary` [name] Host/Origin  → category: A

## 20260928-093807 native CVE-2026-20963
- `remediation.detail` [name] Edition  → category: B
- `remediation.workaround` [context] internet-facing  → category: C
- `severity.adjustment_reason` [context] widely  → category: E

## 20260928-093807 native CVE-2026-46251
- `summary` [world] experimental  → category: A  (added: missed by the pre-screen)
- `severity.adjustment_reason` [world] experimental  → category: A  (added: missed by the pre-screen)
- `severity.adjustment_reason` [context] essentially absent from production deployments  → category: E  (added: missed by the pre-screen)
- `remediation.workaround` [world] experimental  → category: A  (added: missed by the pre-screen)
- `rationale` [world] experimental  → category: A  (added: missed by the pre-screen)
- `rationale` [context] virtually no production kernel enables  → category: E  (added: missed by the pre-screen)

## 20260928-093807 native CVE-2026-70613
- `rationale` [name] CNA's  → category: B

## 20260928-093807 native CVE-2026-79379
- `remediation.detail` [name] ODM/vendor  → category: C

## 20260928-093807 native CVE-2026-86509
- `remediation.detail` [world] end-of-life  → category: A?  (conditional "if it is end-of-life"; reference case, seen before adjudication)
- `remediation.workaround` [name] VLAN/Wi-Fi  → category: C
- `severity.adjustment_reason` [world] consumer router  → category: A  (reference case, seen before adjudication)
- `severity.adjustment_reason` [world] end-of-life  → category: A  (reference case, seen before adjudication)

## 20260928-093807 prompt CVE-2001-1533
- `rationale` [world] end-of-life  → category: A
- `rationale` [world] legacy  → category: D
- `remediation.workaround` [name] DDoS  → category: C
- `rationale` [context] unlikely to be a live CI dependency  → category: E  (added: missed by the pre-screen)

## 20260928-093807 prompt CVE-2002-1774
- `rationale` [world] legacy  → category: D
- `severity.adjustment_reason` [world] legacy  → category: D

## 20260928-093807 prompt CVE-2007-6252
- `rationale` [name] Explorer  → category: A
- `rationale` [name] Internet  → category: A
- `rationale` [world] legacy  → category: D
- `remediation.workaround` [name] Explorer  → category: A
- `remediation.workaround` [name] Internet  → category: A
- `severity.adjustment_reason` [name] Explorer  → category: A
- `severity.adjustment_reason` [name] Internet  → category: A
- `summary` [name] Explorer  → category: A
- `summary` [name] Internet  → category: A
- `summary` [name] Windows  → category: A

## 20260928-093807 prompt CVE-2007-6703
- `rationale` [context] rarely  → category: E
- `summary` [name] Mobile/PocketPC  → category: A
- `summary` [name] Windows  → category: A

## 20260928-093807 prompt CVE-2008-1113
- `remediation.detail` [name] Cisco/Secunia  → category: B

## 20260928-093807 prompt CVE-2008-1146
- `rationale` [world] unsupported  → category: D  (pre-screen false hit: "exploit maturity is unsupported by the references", not vendor support)

## 20260928-093807 prompt CVE-2020-1631
- `rationale` [name] CISA's  → category: B
- `summary` [name] CISA's  → category: B

## 20260928-093807 prompt CVE-2024-12366
- `summary` [name] PandasAI's  → category: B

## 20260928-093807 prompt CVE-2024-28088
- `summary` [name] LangChain's  → category: B

## 20260928-093807 prompt CVE-2024-31224
- `severity.adjustment_reason` [context] internet-exposed  → category: B

## 20260928-093807 prompt CVE-2026-20963
- `remediation.detail` [name] Edition  → category: B
- `severity.adjustment_reason` [context] commonly  → category: E
- `severity.adjustment_reason` [context] internet-exposed  → category: E

## 20260928-093807 prompt CVE-2026-46251
- `summary` [world] experimental  → category: A  (added: missed by the pre-screen)
- `severity.adjustment_reason` [world] experimental  → category: A  (added: missed by the pre-screen)
- `remediation.workaround` [world] experimental  → category: A  (added: missed by the pre-screen)
- `rationale` [world] experimental  → category: A  (added: missed by the pre-screen)

## 20260928-093807 prompt CVE-2026-70613
- `rationale` [name] CWEs  → category: B

## 20260928-093807 prompt CVE-2026-84282
- `impact.worst_case` [name] URLs  → category: B

