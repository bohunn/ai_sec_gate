package io.holbein.ai.secgateway.service;

import java.util.List;

import io.holbein.ai.secgateway.model.MessageParam;
import io.holbein.ai.secgateway.model.MessageResponse;
import io.holbein.ai.secgateway.model.SystemParam;
import io.holbein.ai.secgateway.schema.CveTriageSchema;

public final class StructuredOutputSender implements MessageSender {
  private final AnthropicService anthropic;

  public StructuredOutputSender(AnthropicService anthropic) {
    this.anthropic = anthropic;
  }

  @Override
  public MessageResponse send(
      List<MessageParam> messages, List<SystemParam> system, int maxTokens) {
    return anthropic.send(messages, system, maxTokens, CveTriageSchema.outputConfig());
  }
}
