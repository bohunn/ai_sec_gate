package io.holbein.ai.secgateway.service;

public class ApiException extends RuntimeException {
  public ApiException(String message) {
    super(message);
  }
}
