package io.holbein.ai.secgateway.service;

import java.util.ArrayList;
import java.util.List;

import io.holbein.ai.secgateway.Json;
import io.holbein.ai.secgateway.model.MessageParam;
import io.holbein.ai.secgateway.model.MessageResponse;
import io.holbein.ai.secgateway.model.SystemParam;
import io.holbein.ai.secgateway.schema.CveTriageSchema;

public final class PromptOnlySender implements MessageSender {
  private static final SystemParam SCHEMA_INSTRUCTION =
      new SystemParam("text", schemaInstruction());

  private final AnthropicService anthropic;

  public PromptOnlySender(AnthropicService anthropic) {
    this.anthropic = anthropic;
  }

  @Override
  public MessageResponse send(
      List<MessageParam> messages, List<SystemParam> system, int maxTokens) {
    List<SystemParam> instructed = new ArrayList<>(system);
    instructed.add(SCHEMA_INSTRUCTION);

    MessageResponse response = anthropic.send(messages, instructed, maxTokens, null);
    return response.content() == null ? response : unwrap(response);
  }

  private static String schemaInstruction() {
    return """
        Reply with a single JSON document and nothing else. No markdown fences, no preamble, no \
        commentary before or after. The document must conform exactly to this JSON Schema - every \
        property is required, no extra properties are permitted, and every enum value must be one \
        of the listed strings:

        """
        + Json.API.writeValueAsString(CveTriageSchema.schema());
  }

  private static MessageResponse unwrap(MessageResponse response) {
    List<MessageResponse.ContentBlock> unwrapped = new ArrayList<>();
    for (MessageResponse.ContentBlock block : response.content()) {
      unwrapped.add(
          "text".equals(block.type()) && block.text() != null
              ? new MessageResponse.ContentBlock(block.type(), extractJson(block.text()))
              : block);
    }
    return new MessageResponse(
        response.id(), response.type(), response.role(), response.model(), unwrapped,
        response.stopReason(), response.usage());
  }

  private static String extractJson(String raw) {
    String text = raw.trim();
    int fence = text.indexOf("```");
    if (fence >= 0) {
      int start = text.indexOf('\n', fence);
      int end = text.lastIndexOf("```");
      if (start > 0 && end > start) {
        text = text.substring(start + 1, end).trim();
      }
    }
    int open = text.indexOf('{');
    int close = text.lastIndexOf('}');
    return open >= 0 && close > open ? text.substring(open, close + 1) : text;
  }
}
