package io.holbein.ai.secgateway.experiment;

import java.util.List;

import io.holbein.ai.secgateway.Csv;
import io.holbein.ai.secgateway.model.CveTriage;
import io.holbein.ai.secgateway.model.MessageResponse;
import io.holbein.ai.secgateway.model.TriageResult;
import io.holbein.ai.secgateway.validation.Finding;
import io.holbein.ai.secgateway.validation.GroundingReport;
import io.holbein.ai.secgateway.validation.Violation;

public final class ResultRow {

  private static final List<String> HEADER =
      List.of(
          "cve_id", "stratum", "arm", "run", "first_attempt_valid", "outcome", "attempts",
          "violation_count", "first_violation_path", "first_violation_message",
          "input_tokens", "output_tokens", "latency_ms",
          "verdict", "priority", "confidence", "adjusted_severity", "component_type", "mechanism",
          "grounding_hard_fail", "grounding_soft_fail", "grounding_unverifiable",
          "first_hard_fail_path", "model",
          "first_attempt_outcome", "adjustment_basis", "background_knowledge");

  private ResultRow() {}

  public static String header() {
    return String.join(",", HEADER);
  }

  public static String of(
      String cveId, String stratum, String arm, int run, TriageResult result, long elapsedMs) {

    List<Violation> violations = result.violations();
    Violation first = violations.isEmpty() ? null : violations.get(0);
    CveTriage triage = result.outcome().trustworthy() ? result.triage() : null;
    MessageResponse.Usage usage = result.usage();
    GroundingReport grounding = triage == null ? null : result.groundingOrEmpty();
    Finding firstHard =
        grounding == null || grounding.hardFailures().isEmpty()
            ? null
            : grounding.hardFailures().get(0);

    return String.join(
        ",",
        Csv.escape(cveId), Csv.escape(stratum), Csv.escape(arm), String.valueOf(run),
        String.valueOf(result.outcome() == TriageResult.Outcome.OK),
        Csv.escape(result.outcome().name()), String.valueOf(result.attempts()),
        String.valueOf(violations.size()),
        Csv.escape(first == null ? "" : first.path()),
        Csv.escape(first == null ? "" : first.message()),
        num(usage == null ? null : usage.inputTokens()),
        num(usage == null ? null : usage.outputTokens()),
        String.valueOf(elapsedMs),
        cell(triage, t -> t.verdict().name()),
        cell(triage, t -> t.priority().name()),
        cell(triage, t -> t.confidence().name()),
        cell(triage, t -> t.severity().adjustedSeverity().name()),
        cell(triage, t -> t.affected().componentType().name()),
        cell(triage, t -> t.weakness().mechanism().name()),
        grounding == null ? "" : String.valueOf(grounding.hardFailures().size()),
        grounding == null ? "" : String.valueOf(grounding.softFailures().size()),
        grounding == null ? "" : String.valueOf(grounding.unverifiable().size()),
        Csv.escape(firstHard == null ? "" : firstHard.path()),
        Csv.escape(result.model()),
        result.firstAttempt() == null ? "" : result.firstAttempt().name(),
        cell(triage, t -> t.severity().adjustmentBasis() == null
            ? "" : t.severity().adjustmentBasis().name()),
        cell(triage, t -> String.valueOf(
            t.backgroundKnowledge() == null ? 0 : t.backgroundKnowledge().size())));
  }

  private static String cell(CveTriage triage, java.util.function.Function<CveTriage, String> of) {
    return triage == null ? "" : Csv.escape(of.apply(triage));
  }

  private static String num(Integer value) {
    return value == null ? "" : value.toString();
  }
}
