package io.holbein.ai.secgateway.service;

public record RetryPolicy(int feedbackRetries, int truncationRetries, int maxTokensCeiling) {
  public static RetryPolicy defaults() {
    return new RetryPolicy(2, 1, 16_000);
  }

  public static RetryPolicy singleAttempt() {
    return new RetryPolicy(0, 0, 0);
  }
}
