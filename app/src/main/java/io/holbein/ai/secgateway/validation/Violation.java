package io.holbein.ai.secgateway.validation;

public record Violation(String path, String message) {
  public String format() {
    return (path.isEmpty() ? "(root)" : path) + ": " + message;
  }
}
