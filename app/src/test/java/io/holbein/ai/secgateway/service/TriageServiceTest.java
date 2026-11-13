package io.holbein.ai.secgateway.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import io.holbein.ai.secgateway.Json;
import io.holbein.ai.secgateway.model.CveInput;
import io.holbein.ai.secgateway.model.MessageParam;
import io.holbein.ai.secgateway.model.CveTriage;
import io.holbein.ai.secgateway.model.MessageResponse;
import io.holbein.ai.secgateway.model.SystemParam;
import io.holbein.ai.secgateway.model.TriageResult;
import io.holbein.ai.secgateway.validation.Finding;
import io.holbein.ai.secgateway.validation.GroundingReport;
import org.junit.jupiter.api.Test;

class TriageServiceTest {
  private static final List<SystemParam> SYSTEM = List.of(new SystemParam("text", "test"));

  private static final CveInput INPUT =
      new CveInput("CVE-2019-1010218", "2019-07-22", "Modified", false, null, List.of(),
          "Buffer overflow.", List.of("CWE-120"), null, List.of("application"), List.of(),
          List.of());

  private static MessageResponse respond(String stopReason, String text) {
    return new MessageResponse("msg_1", "message", "assistant", "claude-opus-5",
        text == null ? List.of() : List.of(new MessageResponse.ContentBlock("text", text)),
        stopReason, new MessageResponse.Usage(100, 200));
  }

  private static String validDocument() {
    return Json.API.writeValueAsString(CveTriage.needsHumanReview("CVE-2019-1010218", "fixture"));
  }

  private static TriageResult run(MessageSender sender) {
    return new TriageService(sender).triage(INPUT, SYSTEM, 4096);
  }

  private static final class ScriptedSender implements MessageSender {
    private final java.util.Deque<MessageResponse> script;
    final java.util.List<java.util.List<MessageParam>> conversations = new java.util.ArrayList<>();
    final java.util.List<Integer> budgets = new java.util.ArrayList<>();

    ScriptedSender(MessageResponse... responses) {
      this.script = new java.util.ArrayDeque<>(List.of(responses));
    }

    @Override
    public MessageResponse send(List<MessageParam> messages, List<SystemParam> system, int max) {
      conversations.add(messages);
      budgets.add(max);
      if (script.isEmpty()) {
        throw new AssertionError("sender called more times than the script allows");
      }
      return script.poll();
    }
  }

  private static String invalidDocument() {
    return validDocument().replace("\"NEEDS_HUMAN_REVIEW\"", "\"PROBABLY_FINE\"");
  }

  @Test
  void aSchemaValidResponseIsAccepted() {
    TriageResult result = run((m, s, t) -> respond("end_turn", validDocument()));

    assertEquals(TriageResult.Outcome.OK, result.outcome());
    assertTrue(result.outcome().trustworthy());
    assertEquals(List.of(), result.violations());
    assertEquals("CVE-2019-1010218", result.triage().cveId());
    assertEquals(200, result.usage().outputTokens(), "usage must be recorded for cost tracking");
  }

  @Test
  void aValidResponseIsGroundedAndTheReportTravelsWithTheResult() {
    TriageResult result = run((m, s, t) -> respond("end_turn", validDocument()));

    assertTrue(
        result.grounding().findings().stream()
            .anyMatch(f -> f.path().equals("cve_id") && f.status() == Finding.Status.PASS),
        "grounding must run on schema-valid output");
    assertEquals(
        GroundingReport.EMPTY,
        TriageResult.failed("CVE-0-0", TriageResult.Outcome.REFUSED, "x", List.of(), 1, null)
            .grounding(),
        "a failed result has nothing to ground");
  }

  @Test
  void unparseableOutputIsAValidationFailureNotACrash() {
    TriageResult result = run((m, s, t) -> respond("end_turn", "Here is the JSON: {oops"));

    assertEquals(TriageResult.Outcome.VALIDATION_EXHAUSTED, result.outcome());
    assertEquals(CveTriage.Verdict.NEEDS_HUMAN_REVIEW, result.triage().verdict());
  }

  @Test
  void transportFailureIsClassifiedNotPropagated() {
    TriageResult result =
        run((m, s, t) -> {
          throw new ApiException("429 rate limited");
        });

    assertEquals(TriageResult.Outcome.API_ERROR, result.outcome());
    assertTrue(result.triage().rationale().contains("429"));
  }

  @Test
  void anInvalidResponseIsRetriedWithFeedbackAndCanRecover() {
    ScriptedSender sender =
        new ScriptedSender(
            respond("end_turn", invalidDocument()), respond("end_turn", validDocument()));

    TriageResult result = run(sender);

    assertEquals(TriageResult.Outcome.RECOVERED_AFTER_RETRY, result.outcome());
    assertTrue(result.outcome().trustworthy());
    assertEquals(2, result.attempts());
    assertFalse(
        result.violations().isEmpty(),
        "a repaired response must keep what was wrong, or the experiment loses the reason");
    assertEquals("verdict", result.violations().get(0).path());
    assertEquals(CveTriage.Verdict.NEEDS_HUMAN_REVIEW, result.triage().verdict());
  }

  @Test
  void theRetryCarriesTheConversationAndNamesTheViolation() {
    ScriptedSender sender =
        new ScriptedSender(
            respond("end_turn", invalidDocument()), respond("end_turn", validDocument()));

    run(sender);

    List<MessageParam> second = sender.conversations.get(1);
    assertEquals(3, second.size(), "original user turn, the bad answer, then the complaint");
    assertEquals("assistant", second.get(1).role());
    assertEquals("user", second.get(2).role());

    String feedback = second.get(2).content().toString();
    assertTrue(feedback.contains("verdict:"), "feedback must name the field");
    assertTrue(feedback.contains("PROBABLY_FINE"), "feedback must quote what was wrong");
    assertTrue(feedback.contains("BLOCK"), "feedback must list what is allowed");
  }

  @Test
  void retriesAreBoundedAndExhaustionDegradesGracefully() {
    ScriptedSender sender =
        new ScriptedSender(
            respond("end_turn", invalidDocument()),
            respond("end_turn", invalidDocument()),
            respond("end_turn", invalidDocument()));

    TriageResult result = run(sender);

    assertEquals(TriageResult.Outcome.VALIDATION_EXHAUSTED, result.outcome());
    assertEquals(3, result.attempts(), "one attempt plus two feedback retries");
    assertEquals(3, sender.conversations.size(), "and no more calls than that");
    assertEquals(CveTriage.Verdict.NEEDS_HUMAN_REVIEW, result.triage().verdict());
  }

  @Test
  void singleAttemptPolicyDisablesRetryForFirstAttemptMeasurement() {
    ScriptedSender sender = new ScriptedSender(respond("end_turn", invalidDocument()));

    TriageResult result =
        new TriageService(sender, RetryPolicy.singleAttempt()).triage(INPUT, SYSTEM, 4096);

    assertEquals(TriageResult.Outcome.VALIDATION_EXHAUSTED, result.outcome());
    assertEquals(1, result.attempts());
  }

  @Test
  void truncationRetriesWithABiggerBudgetRatherThanFeedback() {
    ScriptedSender sender =
        new ScriptedSender(respond("max_tokens", "{trunc"), respond("end_turn", validDocument()));

    TriageResult result = run(sender);

    assertEquals(TriageResult.Outcome.RECOVERED_AFTER_RETRY, result.outcome());
    assertEquals(List.of(4096, 8192), sender.budgets, "budget must double, not repeat");
    assertEquals(1, sender.conversations.get(1).size(), "a truncation gets more room, not advice");
  }

  @Test
  void truncationStopsAtTheCeilingInsteadOfDoublingForever() {
    ScriptedSender sender =
        new ScriptedSender(respond("max_tokens", "{a"), respond("max_tokens", "{b"));

    TriageResult result = run(sender);

    assertEquals(TriageResult.Outcome.TRUNCATED, result.outcome());
    assertEquals(2, sender.conversations.size());
  }

  @Test
  void aRefusalIsNotRetried() {
    ScriptedSender sender = new ScriptedSender(respond("refusal", null));

    TriageResult result = run(sender);

    assertEquals(TriageResult.Outcome.REFUSED, result.outcome());
    assertEquals(1, sender.conversations.size(), "retrying a refusal only spends money");
  }

  @Test
  void usageAccumulatesAcrossAttempts() {
    ScriptedSender sender =
        new ScriptedSender(
            respond("end_turn", invalidDocument()), respond("end_turn", validDocument()));

    TriageResult result = run(sender);

    assertEquals(200, result.usage().inputTokens(), "a triage costs every attempt it took");
    assertEquals(400, result.usage().outputTokens());
  }
}
