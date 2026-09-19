package io.holbein.ai.secgateway.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record CreateMessageRequest(
    String model,
    int maxTokens,
    List<MessageParam> messages,
    List<SystemParam> system,
    OutputConfig outputConfig) {
}
