package io.holbein.ai.secgateway.service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.List;

import io.holbein.ai.secgateway.Json;
import io.holbein.ai.secgateway.model.CreateMessageRequest;
import io.holbein.ai.secgateway.model.MessageParam;
import io.holbein.ai.secgateway.model.MessageResponse;
import io.holbein.ai.secgateway.model.OutputConfig;
import io.holbein.ai.secgateway.model.SystemParam;

public class AnthropicService {
  private static final String ANTHROPIC_API = "https://api.anthropic.com/v1/messages";

  /** The model requested on every call; the manifest records it and each result records the
   * model id the API answered with, so the two can be compared after the fact. */
  public static final String MODEL = "claude-sonnet-5";

  private final HttpClient client;
  private final String apiKey;

  public AnthropicService() {
    this.apiKey = requireApiKey();
    this.client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(20)).build();
  }

  private static String requireApiKey() {
    String key = System.getenv("ANTHROPIC_API_KEY");
    if (key == null || key.isBlank()) {
      throw new IllegalStateException("ANTHROPIC_API_KEY is not set");
    }
    return key;
  }

  public MessageResponse send(
      List<MessageParam> messages, List<SystemParam> system, int maxTokens,
      OutputConfig outputConfig) {
    HttpResponse<String> response = HttpRetry
        .send(() -> sendAnthropicRequest(messages, system, maxTokens, outputConfig));

    if (response.statusCode() != 200) {
      throw new ApiException(
          "Anthropic API returned " + response.statusCode() + ": " + response.body());
    }
    return Json.API.readValue(response.body(), MessageResponse.class);
  }

  private HttpResponse<String> sendAnthropicRequest(
      List<MessageParam> messageParam,
      List<SystemParam> systemParam,
      int maxTokens,
      OutputConfig outputConfig) {
    String json = Json.API.writeValueAsString(
        new CreateMessageRequest(
            MODEL, maxTokens, messageParam, systemParam, outputConfig));

    HttpRequest request = HttpRequest.newBuilder(URI.create(ANTHROPIC_API))
        .method("POST", BodyPublishers.ofString(json))
        .setHeader("content-type", "application/json")
        .setHeader("x-api-key", apiKey)
        .setHeader("anthropic-version", "2023-06-01")
        .timeout(Duration.ofMinutes(5))
        .build();

    try {
      return client.send(request, BodyHandlers.ofString());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
