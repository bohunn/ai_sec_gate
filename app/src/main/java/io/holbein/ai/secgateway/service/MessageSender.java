package io.holbein.ai.secgateway.service;

import java.util.List;

import io.holbein.ai.secgateway.model.MessageParam;
import io.holbein.ai.secgateway.model.MessageResponse;
import io.holbein.ai.secgateway.model.SystemParam;

@FunctionalInterface
public interface MessageSender {
  MessageResponse send(List<MessageParam> messages, List<SystemParam> system, int maxTokens);
}
