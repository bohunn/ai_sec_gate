package io.holbein.ai.secgateway.model;

import java.util.List;

public record MessageResponse(
    String id,
    String type,
    String role,
    String model,
    List<ContentBlock> content,
    String stopReason,
    Usage usage) {
  public record ContentBlock(String type, String text) {
  }

  public record Usage(Integer inputTokens, Integer outputTokens) {
  }

  public String outputJson() {
    for (ContentBlock block : content) {
      if ("text".equals(block.type()) && block.text() != null) {
        return block.text();
      }
    }
    throw new IllegalStateException(
        "No text block in response (stop_reason=" + stopReason + ", id=" + id + ")");
  }
}
