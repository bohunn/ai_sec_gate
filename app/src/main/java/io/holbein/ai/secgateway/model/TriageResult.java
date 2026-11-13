package io.holbein.ai.secgateway.model;

import java.util.List;

import io.holbein.ai.secgateway.validation.GroundingReport;
import io.holbein.ai.secgateway.validation.Violation;

public record TriageResult(
    CveTriage triage,
    Outcome outcome,
    List<Violation> violations,
    int attempts,
    MessageResponse.Usage usage,
    GroundingReport grounding,
    String model) {
  public enum Outcome {
    OK,

    RECOVERED_AFTER_RETRY,

    VALIDATION_EXHAUSTED,

    REFUSED,

    TRUNCATED,

    API_ERROR;

    public boolean trustworthy() {
      return this == OK || this == RECOVERED_AFTER_RETRY;
    }
  }

  public static TriageResult valid(
      CveTriage triage,
      List<Violation> repaired,
      int attempts,
      MessageResponse.Usage usage,
      GroundingReport grounding,
      String model) {
    Outcome outcome = attempts == 1 ? Outcome.OK : Outcome.RECOVERED_AFTER_RETRY;
    return new TriageResult(triage, outcome, repaired, attempts, usage, grounding, model);
  }

  /** Results read from older raw files carry no grounding section. */
  public GroundingReport groundingOrEmpty() {
    return grounding == null ? GroundingReport.EMPTY : grounding;
  }

  public static TriageResult failed(
      String cveId,
      Outcome outcome,
      String reason,
      List<Violation> violations,
      int attempts,
      MessageResponse.Usage usage,
      String model) {
    return new TriageResult(
        CveTriage.needsHumanReview(cveId, reason), outcome, violations, attempts, usage,
        GroundingReport.EMPTY, model);
  }
}
