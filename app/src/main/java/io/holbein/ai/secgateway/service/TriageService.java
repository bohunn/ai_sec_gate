package io.holbein.ai.secgateway.service;

import java.util.ArrayList;
import java.util.List;

import io.holbein.ai.secgateway.Json;
import io.holbein.ai.secgateway.model.CveInput;
import io.holbein.ai.secgateway.model.CveTriage;
import io.holbein.ai.secgateway.model.MessageParam;
import io.holbein.ai.secgateway.model.MessageResponse;
import io.holbein.ai.secgateway.model.SystemParam;
import io.holbein.ai.secgateway.model.TriageResult;
import io.holbein.ai.secgateway.schema.CveTriageSchema;
import io.holbein.ai.secgateway.validation.GroundingReport;
import io.holbein.ai.secgateway.validation.GroundingValidator;
import io.holbein.ai.secgateway.validation.SchemaValidator;
import io.holbein.ai.secgateway.validation.Violation;
import tools.jackson.databind.JsonNode;

public class TriageService {
  private final MessageSender sender;
  private final RetryPolicy policy;

  public TriageService(MessageSender sender) {
    this(sender, RetryPolicy.defaults());
  }

  public TriageService(MessageSender sender, RetryPolicy policy) {
    this.sender = sender;
    this.policy = policy;
  }

  public TriageResult triage(CveInput input, List<SystemParam> system, int maxTokens) {
    List<MessageParam> conversation = new ArrayList<>();
    conversation.add(new MessageParam("user", Json.API.writeValueAsString(input)));

    int attempt = 0;
    int budget = maxTokens;
    int feedbackRetriesLeft = policy.feedbackRetries();
    int truncationRetriesLeft = policy.truncationRetries();
    MessageResponse.Usage usage = null;
    String model = null;
    List<Violation> firstFailure = List.of();

    while (true) {
      attempt++;

      MessageResponse response;
      try {
        response = sender.send(List.copyOf(conversation), system, budget);
      } catch (ApiException e) {
        return TriageResult.failed(
            input.cveId(), TriageResult.Outcome.API_ERROR, e.getMessage(), List.of(), attempt, usage, model);
      } catch (RuntimeException e) {
        return TriageResult.failed(
            input.cveId(), TriageResult.Outcome.API_ERROR,
            e.getClass().getSimpleName() + ": " + e.getMessage(), List.of(), attempt, usage, model);
      }

      usage = add(usage, response.usage());
      model = response.model();

      if ("refusal".equals(response.stopReason())) {
        return TriageResult.failed(
            input.cveId(), TriageResult.Outcome.REFUSED,
            "the model declined to answer", List.of(), attempt, usage, model);
      }

      if ("max_tokens".equals(response.stopReason())) {
        int raised = budget * 2;
        if (truncationRetriesLeft > 0 && raised <= policy.maxTokensCeiling()) {
          truncationRetriesLeft--;
          budget = raised;
          continue;
        }
        return TriageResult.failed(
            input.cveId(), TriageResult.Outcome.TRUNCATED,
            "response hit the max_tokens ceiling", List.of(), attempt, usage, model);
      }

      String document;
      try {
        document = response.outputJson();
      } catch (IllegalStateException e) {
        return TriageResult.failed(
            input.cveId(), TriageResult.Outcome.API_ERROR, e.getMessage(), List.of(), attempt,
            usage, model);
      }

      List<Violation> violations;
      JsonNode parsed = null;
      try {
        parsed = Json.API.readTree(document);
        violations = SchemaValidator.validate(CveTriageSchema.schema(), parsed);
      } catch (RuntimeException e) {
        violations = List.of(new Violation("", "the response was not valid JSON"));
      }

      if (violations.isEmpty()) {
        CveTriage triage = Json.API.treeToValue(parsed, CveTriage.class);
        // Grounding findings are recorded, not fed back: the schema loop repairs shape, and
        // whether a grounding failure should cost another attempt is a separate decision
        // (VALIDATION.md, decision 2).
        GroundingReport grounding = GroundingValidator.validate(input, triage);
        return TriageResult.valid(triage, firstFailure, attempt, usage, grounding, model);
      }
      if (firstFailure.isEmpty()) {
        firstFailure = violations;
      }

      if (feedbackRetriesLeft == 0) {
        return TriageResult.failed(
            input.cveId(), TriageResult.Outcome.VALIDATION_EXHAUSTED,
            violations.size() + " unresolved schema violation(s) after " + attempt
                + " attempt(s)",
            violations, attempt, usage, model);
      }
      feedbackRetriesLeft--;

      conversation.add(new MessageParam("assistant", document));
      conversation.add(new MessageParam("user", feedback(violations)));
    }
  }

  private static String feedback(List<Violation> errors) {
    StringBuilder message = new StringBuilder("Your previous response did not satisfy the required schema:\n");
    for (Violation error : errors) {
      message.append("- ").append(error.format()).append('\n');
    }
    return message
        .append("\nReturn the corrected document. Change only what is listed above.")
        .toString();
  }

  private static MessageResponse.Usage add(MessageResponse.Usage running, MessageResponse.Usage n) {
    if (n == null) {
      return running;
    }
    if (running == null) {
      return n;
    }
    return new MessageResponse.Usage(
        sum(running.inputTokens(), n.inputTokens()), sum(running.outputTokens(), n.outputTokens()));
  }

  private static Integer sum(Integer a, Integer b) {
    if (a == null) {
      return b;
    }
    return b == null ? a : a + b;
  }
}
