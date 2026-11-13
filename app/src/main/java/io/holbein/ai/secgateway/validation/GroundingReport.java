package io.holbein.ai.secgateway.validation;

import java.util.List;

/** The findings of {@link GroundingValidator} for one triage. */
public record GroundingReport(List<Finding> findings) {
  public static final GroundingReport EMPTY = new GroundingReport(List.of());

  public List<Finding> hardFailures() {
    return findings.stream().filter(Finding::hardFailure).toList();
  }

  public List<Finding> softFailures() {
    return findings.stream().filter(Finding::softFailure).toList();
  }

  public List<Finding> unverifiable() {
    return findings.stream().filter(f -> f.status() == Finding.Status.UNVERIFIABLE).toList();
  }

  public long passed() {
    return findings.stream().filter(f -> f.status() == Finding.Status.PASS).count();
  }

  /** True when no check against a trusted oracle failed. Soft flags do not count. */
  public boolean grounded() {
    return hardFailures().isEmpty();
  }

  public String summary() {
    return hardFailures().size() + " hard, " + softFailures().size() + " soft, "
        + unverifiable().size() + " unverifiable, " + passed() + " passed";
  }
}
