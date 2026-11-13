package io.holbein.ai.secgateway.validation;

/**
 * One grounding or consistency check applied to a schema-valid triage.
 *
 * <p>{@code status} says what the check found. {@code UNVERIFIABLE} is reported, not skipped, when
 * the input carries no oracle for the field, so that coverage can be counted per run.
 *
 * <p>{@code severity} says how much the oracle is trusted. {@code HARD} checks compare against data
 * the model was told to copy or derive mechanically; a failure is a grounding error. {@code SOFT}
 * checks compare against a noisy oracle (stale CPE data, the CVSS v2 impact mapping, reference
 * tags) and a failure is a flag for a reviewer, not a verdict.
 */
public record Finding(String path, Status status, Severity severity, String message) {
  public enum Status {
    PASS,
    FAIL,
    UNVERIFIABLE
  }

  public enum Severity {
    HARD,
    SOFT
  }

  public static Finding pass(String path, String message) {
    return new Finding(path, Status.PASS, Severity.HARD, message);
  }

  public static Finding fail(String path, Severity severity, String message) {
    return new Finding(path, Status.FAIL, severity, message);
  }

  public static Finding unverifiable(String path, String message) {
    return new Finding(path, Status.UNVERIFIABLE, Severity.HARD, message);
  }

  public boolean failed() {
    return status == Status.FAIL;
  }

  public boolean hardFailure() {
    return failed() && severity == Severity.HARD;
  }

  public boolean softFailure() {
    return failed() && severity == Severity.SOFT;
  }

  public String format() {
    String tag = status == Status.FAIL ? severity + " " + status : status.name();
    return "[" + tag + "] " + path + ": " + message;
  }
}
