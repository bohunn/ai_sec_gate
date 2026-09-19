package io.holbein.ai.secgateway.service;

import java.net.http.HttpResponse;
import java.util.function.Supplier;

public final class HttpRetry {
  private static final int MAX_ATTEMPTS = 4;
  private static final long BASE_DELAY_MS = 1_000;

  private static final long RATE_LIMIT_DELAY_MS = 10_000;

  private HttpRetry() {}

  static HttpResponse<String> send(Supplier<HttpResponse<String>> call) {
    for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        HttpResponse<String> response = call.get();
        if (!retryable(response.statusCode()) || attempt == MAX_ATTEMPTS) {
          return response;
        }
        pause(response.statusCode() == 429 ? RATE_LIMIT_DELAY_MS * attempt
            : delayFor(attempt, response));
      } catch (RuntimeException e) {
        if (attempt == MAX_ATTEMPTS) {
          throw e;
        }
        pause(delayFor(attempt, null));
      }
    }
    throw new IllegalStateException("unreachable");
  }

  private static boolean retryable(int status) {
    return status == 429 || status == 408 || status >= 500;
  }

  private static long delayFor(int attempt, HttpResponse<String> response) {
    if (response != null) {
      String retryAfter = response.headers().firstValue("retry-after").orElse(null);
      if (retryAfter != null) {
        try {
          return Long.parseLong(retryAfter.trim()) * 1_000;
        } catch (NumberFormatException ignored) {
        }
      }
    }
    long exponential = BASE_DELAY_MS * (1L << (attempt - 1));
    return exponential + (long) (Math.random() * BASE_DELAY_MS);
  }

  public static void pause(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("interrupted while waiting", e);
    }
  }
}
