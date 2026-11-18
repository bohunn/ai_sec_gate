package io.holbein.ai.secgateway.model;

import java.util.List;

import io.holbein.ai.secgateway.schema.Field;

public record CveTriage(
    @Field("The CVE identifier being triaged, exactly as it appears in the input.")
    String cveId,
    @Field("Two or three plain-language sentences a developer can read in ten seconds: what an"
        + " attacker can do and to what. State the consequence - the flaw class belongs in"
        + " weakness.mechanism, so do not restate it here. No CVSS jargon.")
    String summary,
    Affected affected,
    Weakness weakness,
    Severity severity,
    Exploitability exploitability,
    Impact impact,
    Remediation remediation,
    @Field("The gate decision. BLOCK stops the build. WARN records the finding and lets it"
        + " through. ALLOW means no action needed. NEEDS_HUMAN_REVIEW when the input is too thin"
        + " to decide - use it instead of guessing.")
    Verdict verdict,
    @Field("Remediation priority. P0 is same-day, P1 this sprint, P2 next quarter, P3 backlog.")
    Priority priority,
    @Field("Your confidence in the verdict given only the supplied input. Use LOW when a gap"
        + " listed in data_gaps bears on the verdict itself, not merely on a detail.")
    Confidence confidence,
    @Field("Two or three sentences tying severity, exploitability and remediation effort to the"
        + " verdict. This is what a reviewer reads when they disagree with the gate.")
    String rationale,
    @Field("Facts you needed but the input did not provide, as short noun phrases (e.g. 'no CVSS"
        + " v3 metrics', 'no fixed version published'). Empty array when the input was sufficient.")
    List<String> dataGaps,
    @Field("Facts this triage relies on that come from your own knowledge rather than from the"
        + " record: vendor support or end-of-life status, what a product name refers to, how a"
        + " component is usually deployed, a well-known alias. One short declarative sentence"
        + " each. Empty array when every claim in this document comes from the record. Anything"
        + " from memory goes here and nowhere else: a fact from memory inside a prose field is a"
        + " violation.")
    List<String> backgroundKnowledge,
    @Field("At most three of the most useful reference URLs from the input - prefer vendor"
        + " advisories and patch commits over mailing-list archives. Empty array if the input"
        + " lists none.")
    List<String> keyReferences) {
  public static CveTriage needsHumanReview(String cveId, String reason) {
    return new CveTriage(
        cveId,
        "Automated triage did not complete: " + reason,
        new Affected(null, null, ComponentType.UNKNOWN, "unknown", null),
        new Weakness(Mechanism.UNKNOWN, List.of()),
        new Severity(null, SeverityLevel.UNKNOWN, SeverityLevel.UNKNOWN, AdjustmentBasis.NONE,
            "Not assessed."),
        new Exploitability(
            AttackVector.UNKNOWN, PrivilegesRequired.UNKNOWN, null,
            ExploitMaturity.UNKNOWN, Likelihood.LOW),
        new Impact(ImpactLevel.UNKNOWN, ImpactLevel.UNKNOWN, ImpactLevel.UNKNOWN, "Not assessed."),
        new Remediation(RemediationAction.MONITOR, "Triage this CVE by hand.", null, Effort.UNKNOWN),
        Verdict.NEEDS_HUMAN_REVIEW,
        Priority.P2,
        Confidence.LOW,
        "The gate could not produce a trustworthy verdict: " + reason,
        List.of(reason),
        List.of(),
        List.of());
  }

  public record Affected(
      @Field(value = "Vendor name from the input, or null if it does not state one.",
          nullable = true)
      String vendor,
      @Field(value = "Product or library name, or null if the input does not name one.",
          nullable = true)
      String product,
      @Field("What kind of thing is affected. When the input carries cpe_categories, honour it:"
          + " 'operating_system' means OPERATING_SYSTEM or OS_PACKAGE, 'hardware' means FIRMWARE,"
          + " and 'application' still leaves LIBRARY, APPLICATION and PLUGIN to judge from the"
          + " description. Use UNKNOWN when cpe_categories is empty and the description does not"
          + " make the answer clear.")
      ComponentType componentType,
      @Field("Human-readable version range that is vulnerable, derived from the affected ranges"
          + " (e.g. '< 2.4.1' or 'all versions up to and including 1.9').")
      String vulnerableVersions,
      @Field(value = "First version containing the fix, or null if the input states none. Never"
          + " guess a version number.", nullable = true)
      String fixedVersion) {
  }

  public record Weakness(
      @Field("The class of flaw. Derive it from cwe_ids when the input supplies them (CWE-502 is"
          + " DESERIALIZATION, CWE-22 is PATH_TRAVERSAL, CWE-79 and CWE-89 are INJECTION,"
          + " CWE-119/120/125/787 are MEMORY_SAFETY). Otherwise infer it from the description."
          + " OTHER means the flaw is clear but fits no listed class; UNKNOWN means the input does"
          + " not say enough to classify it.")
      Mechanism mechanism,
      @Field("CWE identifiers copied from the input, e.g. ['CWE-119']. Empty array if the input"
          + " lists none. Never introduce a CWE that is not in the input.")
      List<String> cweIds) {
  }

  public record Severity(
      @Field(value = "CVSS base score copied verbatim from the input. Null if it carries no CVSS"
          + " metrics.", nullable = true)
      Double nvdBaseScore,
      @Field("Base severity as published by NVD. UNKNOWN when the input has no CVSS metrics.")
      SeverityLevel nvdSeverity,
      @Field("Your severity after weighing real-world exploitability and reachability. May differ"
          + " from nvd_severity in either direction.")
      SeverityLevel adjustedSeverity,
      @Field("Why adjusted_severity differs from nvd_severity. NONE when they are equal."
          + " EXPLOIT_EVIDENCE: exploit tags, a KEV listing or exploit maturity in the input."
          + " REACHABILITY: attack vector, privileges or user interaction in the input."
          + " FIX_AVAILABILITY: whether the input states a fix. RECORD_QUALITY: the record is"
          + " disputed, rejected or too thin to trust the NVD score. PRODUCT_LIFECYCLE: the"
          + " product's support status, which the record does not state. DEPLOYMENT_CONTEXT: how"
          + " the component is usually deployed, which the record does not state. The last two"
          + " rest on knowledge from outside the record and are only allowed when"
          + " background_knowledge declares that knowledge.")
      AdjustmentBasis adjustmentBasis,
      @Field("One sentence justifying adjusted_severity. If it equals nvd_severity, say why the"
          + " NVD score is a fair reflection.")
      String adjustmentReason) {
  }

  public record Exploitability(
      @Field("Where the attacker must be positioned, from the CVSS vector when present.")
      AttackVector attackVector,
      @Field("Privileges the attacker needs before exploiting.")
      PrivilegesRequired privilegesRequired,
      @Field(value = "Whether a victim must take an action. Null if the input does not say.",
          nullable = true)
      Boolean userInteractionRequired,
      @Field("Only raise above UNPROVEN when the references or tags in the input support it (e.g."
          + " an Exploit tag, a Metasploit module, a KEV listing). Do not infer from memory.")
      ExploitMaturity exploitMaturity,
      @Field("Practical likelihood of exploitation against a typical deployment of this component.")
      Likelihood likelihood) {
  }

  public record Impact(
      @Field("Confidentiality impact.")
      ImpactLevel confidentiality,
      @Field("Integrity impact.")
      ImpactLevel integrity,
      @Field("Availability impact.")
      ImpactLevel availability,
      @Field("One concrete sentence describing the worst realistic outcome, e.g. 'Remote attacker"
          + " crashes the service with a crafted request.'")
      String worstCase) {
  }

  public record Remediation(
      @Field("The single primary action the owning team should take.")
      RemediationAction action,
      @Field("What to actually do, in one or two imperative sentences.")
      String detail,
      @Field(value = "A mitigation that reduces risk without upgrading, or null if the input knows"
          + " of none.", nullable = true)
      String workaround,
      @Field("Rough effort for the action: TRIVIAL is a patch-version bump, SIGNIFICANT implies a"
          + " breaking change or a rewrite.")
      Effort effort) {
  }

  public enum ComponentType {
    LIBRARY,
    OS_PACKAGE,
    APPLICATION,
    OPERATING_SYSTEM,
    FIRMWARE,
    PLUGIN,
    HOSTED_SERVICE,
    UNKNOWN
  }

  public enum Mechanism {
    MEMORY_SAFETY,
    INJECTION,
    AUTHN_BYPASS,
    AUTHZ_FLAW,
    DESERIALIZATION,
    PATH_TRAVERSAL,
    CRYPTO_WEAKNESS,
    RACE_CONDITION,
    INFO_DISCLOSURE,
    RESOURCE_EXHAUSTION,
    SUPPLY_CHAIN,
    MISCONFIGURATION,
    OTHER,
    UNKNOWN
  }

  public enum Verdict {
    BLOCK,
    WARN,
    ALLOW,
    NEEDS_HUMAN_REVIEW;

    public boolean failsBuild() {
      return this == BLOCK;
    }
  }

  public enum Priority {
    P0,
    P1,
    P2,
    P3
  }

  public enum Confidence {
    LOW,
    MEDIUM,
    HIGH
  }

  public enum SeverityLevel {
    NONE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
    UNKNOWN
  }

  public enum AdjustmentBasis {
    NONE,
    EXPLOIT_EVIDENCE,
    REACHABILITY,
    FIX_AVAILABILITY,
    RECORD_QUALITY,
    PRODUCT_LIFECYCLE,
    DEPLOYMENT_CONTEXT
  }

  public enum AttackVector {
    NETWORK,
    ADJACENT,
    LOCAL,
    PHYSICAL,
    UNKNOWN
  }

  public enum PrivilegesRequired {
    NONE,
    LOW,
    HIGH,
    UNKNOWN
  }

  public enum ExploitMaturity {
    UNKNOWN,
    UNPROVEN,
    PROOF_OF_CONCEPT,
    FUNCTIONAL,
    WEAPONIZED,
    ACTIVELY_EXPLOITED
  }

  public enum Likelihood {
    LOW,
    MEDIUM,
    HIGH
  }

  public enum ImpactLevel {
    NONE,
    LOW,
    HIGH,
    UNKNOWN
  }

  public enum RemediationAction {
    UPGRADE,
    PATCH,
    CONFIG_CHANGE,
    REMOVE_DEPENDENCY,
    MONITOR,
    NO_FIX_AVAILABLE
  }

  public enum Effort {
    TRIVIAL,
    MODERATE,
    SIGNIFICANT,
    UNKNOWN
  }
}
