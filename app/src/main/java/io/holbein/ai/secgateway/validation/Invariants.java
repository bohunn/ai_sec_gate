package io.holbein.ai.secgateway.validation;

import java.util.EnumMap;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import io.holbein.ai.secgateway.model.CveInput;
import io.holbein.ai.secgateway.model.CveTriage;
import io.holbein.ai.secgateway.model.CveTriage.AttackVector;
import io.holbein.ai.secgateway.model.CveTriage.Confidence;
import io.holbein.ai.secgateway.model.CveTriage.ExploitMaturity;
import io.holbein.ai.secgateway.model.CveTriage.Likelihood;
import io.holbein.ai.secgateway.model.CveTriage.Priority;
import io.holbein.ai.secgateway.model.CveTriage.RemediationAction;
import io.holbein.ai.secgateway.model.CveTriage.SeverityLevel;
import io.holbein.ai.secgateway.model.CveTriage.Verdict;
import io.holbein.ai.secgateway.validation.Finding.Severity;

/**
 * Consistency invariants between fields of one triage (and the record's status). These do not
 * need an oracle: a document that violates one contradicts itself. Numbered as in VALIDATION.md.
 */
public final class Invariants {
  /**
   * The one sentence of the system prompt that N4 and N5 enforce. {@code GateCli} appends it to
   * the prompt from here, so the rule and its check cannot drift apart.
   */
  public static final String BLOCK_RULE =
      "Reserve BLOCK for vulnerabilities that are both reachable over the network and have a"
          + " published fix.";

  private static final int MIN_REASON_CHARS = 20;
  private static final Set<RemediationAction> FIXING =
      EnumSet.of(RemediationAction.UPGRADE, RemediationAction.PATCH);

  /** N8: the priority band each adjusted severity may carry (one step of slack either way). */
  private static final Map<SeverityLevel, Set<Priority>> PRIORITY_BAND =
      new EnumMap<>(Map.of(
          SeverityLevel.CRITICAL, EnumSet.of(Priority.P0, Priority.P1),
          SeverityLevel.HIGH, EnumSet.of(Priority.P0, Priority.P1, Priority.P2),
          SeverityLevel.MEDIUM, EnumSet.of(Priority.P1, Priority.P2, Priority.P3),
          SeverityLevel.LOW, EnumSet.of(Priority.P2, Priority.P3),
          SeverityLevel.NONE, EnumSet.of(Priority.P3),
          SeverityLevel.UNKNOWN, EnumSet.allOf(Priority.class)));

  private Invariants() {
  }

  static void check(CveInput in, CveTriage out, List<Finding> findings) {
    CveTriage.Affected a = out.affected();
    CveTriage.Severity s = out.severity();
    CveTriage.Exploitability e = out.exploitability();
    RemediationAction action = out.remediation().action();
    Verdict verdict = out.verdict();

    // N1a / N1b: the remediation action and the fixed version must tell the same story.
    findings.add(rule("invariant.N1a", Severity.HARD,
        action != RemediationAction.NO_FIX_AVAILABLE || a.fixedVersion() == null,
        "NO_FIX_AVAILABLE pairs with fixed_version == null",
        "action is NO_FIX_AVAILABLE but fixed_version is " + a.fixedVersion()));
    findings.add(rule("invariant.N1b", Severity.HARD,
        a.fixedVersion() == null || FIXING.contains(action),
        "a stated fixed_version pairs with UPGRADE or PATCH",
        "fixed_version " + a.fixedVersion() + " is stated but action is " + action));

    // N2: a severity adjustment needs a real reason.
    String reason = s.adjustmentReason() == null ? "" : s.adjustmentReason().trim();
    findings.add(rule("invariant.N2", Severity.HARD,
        s.adjustedSeverity() == s.nvdSeverity() || reason.length() >= MIN_REASON_CHARS,
        "adjusted == nvd, or the adjustment is justified",
        "adjusted_severity " + s.adjustedSeverity() + " differs from nvd_severity "
            + s.nvdSeverity() + " but adjustment_reason is trivial: \"" + reason + "\""));

    // N3: the two copied NVD fields are absent or present together.
    boolean unknown = s.nvdSeverity() == SeverityLevel.UNKNOWN;
    findings.add(rule("invariant.N3", Severity.HARD, unknown == (s.nvdBaseScore() == null),
        "nvd_severity UNKNOWN iff nvd_base_score null",
        "nvd_severity is " + s.nvdSeverity() + " while nvd_base_score is " + s.nvdBaseScore()));

    // N4 / N5: BLOCK_RULE.
    if (verdict == Verdict.BLOCK) {
      findings.add(rule("invariant.N4", Severity.HARD, e.attackVector() == AttackVector.NETWORK,
          "BLOCK is network reachable",
          "BLOCK with attack_vector " + e.attackVector() + " (BLOCK is reserved for NETWORK)"));
      findings.add(rule("invariant.N5", Severity.HARD,
          a.fixedVersion() != null || FIXING.contains(action),
          "BLOCK has a published fix",
          "BLOCK without a fix: fixed_version is null and action is " + action));
    }

    // N6: a rejected record is not a vulnerability.
    if ("Rejected".equalsIgnoreCase(in.vulnStatus())) {
      findings.add(rule("invariant.N6", Severity.HARD,
          verdict == Verdict.ALLOW && s.adjustedSeverity() == SeverityLevel.NONE,
          "rejected record is ALLOW / NONE",
          "record is Rejected but verdict is " + verdict + " and adjusted_severity "
              + s.adjustedSeverity()));
    }

    // N7: asking for a human means the model is not confident.
    if (verdict == Verdict.NEEDS_HUMAN_REVIEW) {
      findings.add(rule("invariant.N7", Severity.HARD, out.confidence() == Confidence.LOW,
          "NEEDS_HUMAN_REVIEW carries LOW confidence",
          "NEEDS_HUMAN_REVIEW with confidence " + out.confidence()));
    }

    // N8: priority tracks adjusted severity within one step.
    Set<Priority> band = PRIORITY_BAND.get(s.adjustedSeverity());
    findings.add(rule("invariant.N8", Severity.SOFT, band.contains(out.priority()),
        "priority within the band for " + s.adjustedSeverity(),
        "priority " + out.priority() + " is outside " + band + " for adjusted_severity "
            + s.adjustedSeverity()));

    // N9: something exploited in the wild is likely to be exploited.
    if (e.exploitMaturity() == ExploitMaturity.ACTIVELY_EXPLOITED) {
      findings.add(rule("invariant.N9", Severity.SOFT, e.likelihood() == Likelihood.HIGH,
          "ACTIVELY_EXPLOITED implies HIGH likelihood",
          "ACTIVELY_EXPLOITED with likelihood " + e.likelihood()));
    }

    // N10: ALLOW means there is nothing worth acting on.
    if (verdict == Verdict.ALLOW) {
      findings.add(rule("invariant.N10", Severity.SOFT,
          s.adjustedSeverity() == SeverityLevel.NONE || s.adjustedSeverity() == SeverityLevel.LOW,
          "ALLOW pairs with NONE or LOW severity",
          "ALLOW with adjusted_severity " + s.adjustedSeverity()));
    }
  }

  private static Finding rule(
      String id, Severity severity, boolean ok, String passed, String failed) {
    return ok ? Finding.pass(id, passed) : Finding.fail(id, severity, failed);
  }
}
