package io.holbein.ai.secgateway.experiment;

import java.util.List;

import io.holbein.ai.secgateway.Csv;
import io.holbein.ai.secgateway.model.CveTriage;
import io.holbein.ai.secgateway.model.MessageResponse;
import io.holbein.ai.secgateway.model.TriageResult;
import io.holbein.ai.secgateway.validation.Violation;

public final class ResultRow {

  private static final List<String> HEADER =
      List.of(
          "cve_id", "stratum", "arm", "run", "first_attempt_valid", "outcome", "attempts",
          "violation_count", "first_violation_path", "first_violation_message",
          "input_tokens", "output_tokens", "latency_ms",
          "verdict", "priority", "confidence", "adjusted_severity", "component_type", "mechanism");

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
        cell(triage, t -> t.weakness().mechanism().name()));
  }

  private static String cell(CveTriage triage, java.util.function.Function<CveTriage, String> of) {
    return triage == null ? "" : Csv.escape(of.apply(triage));
  }

  private static String num(Integer value) {
    return value == null ? "" : value.toString();
  }
}
