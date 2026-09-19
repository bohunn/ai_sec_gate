package io.holbein.ai.secgateway.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import io.holbein.ai.secgateway.Json;
import io.holbein.ai.secgateway.model.CveTriage;
import io.holbein.ai.secgateway.schema.CveTriageSchema;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

class SchemaValidatorTest {
  private static JsonNode valid() {
    return Json.API.valueToTree(CveTriage.needsHumanReview("CVE-2019-1010218", "fixture"));
  }

  private static List<Violation> validate(JsonNode document) {
    return SchemaValidator.validate(CveTriageSchema.schema(), document);
  }

  private static String paths(List<Violation> violations) {
    return violations.stream().map(Violation::path).sorted().toList().toString();
  }

  @Test
  void aValidDocumentProducesNoViolations() {
    assertEquals(List.of(), validate(valid()));
  }

  @Test
  void missingRequiredFieldIsReportedByPath() {
    JsonNode doc = valid();
    ((tools.jackson.databind.node.ObjectNode) doc).remove("rationale");

    List<Violation> violations = validate(doc);

    assertEquals(1, violations.size());
    assertEquals("rationale", violations.get(0).path());
    assertTrue(violations.get(0).message().contains("missing"));
  }

  @Test
  void unknownEnumValueListsWhatWasAllowed() {
    JsonNode doc = valid();
    ((tools.jackson.databind.node.ObjectNode) doc).put("verdict", "MEDIUM-HIGH");

    List<Violation> violations = validate(doc);

    assertEquals(1, violations.size());
    assertEquals("verdict", violations.get(0).path());
    assertTrue(violations.get(0).message().contains("MEDIUM-HIGH"), "must quote what was sent");
    assertTrue(violations.get(0).message().contains("BLOCK"), "must list the allowed values");
  }

  @Test
  void extraFieldIsRejected() {
    JsonNode doc = valid();
    ((tools.jackson.databind.node.ObjectNode) doc).put("severity_score", 9.8);

    List<Violation> violations = validate(doc);

    assertEquals("[severity_score]", paths(violations));
    assertTrue(violations.get(0).message().contains("unexpected"));
  }

  @Test
  void wrongTypeIsReportedInsideNestedObjects() {
    JsonNode doc = valid();
    ((tools.jackson.databind.node.ObjectNode) doc.get("severity")).put("nvd_base_score", "7.5");

    List<Violation> violations = validate(doc);

    assertEquals("[severity.nvd_base_score]", paths(violations));
    assertTrue(violations.get(0).message().contains("expected"));
  }

  @Test
  void nullIsAcceptedOnlyWhereTheSchemaAllowsIt() {
    JsonNode nullable = valid();
    ((tools.jackson.databind.node.ObjectNode) nullable.get("affected")).putNull("fixed_version");
    assertEquals(List.of(), validate(nullable), "fixed_version is an anyOf null union");

    JsonNode notNullable = valid();
    ((tools.jackson.databind.node.ObjectNode) notNullable).putNull("summary");
    assertEquals("[summary]", paths(validate(notNullable)));
  }

  @Test
  void arrayElementsAreValidatedByIndex() {
    JsonNode doc = valid();
    ((tools.jackson.databind.node.ObjectNode) doc).putArray("data_gaps").add("ok").add(42);

    List<Violation> violations = validate(doc);

    assertEquals("[data_gaps[1]]", paths(violations));
  }

  @Test
  void violationsAreCappedSoFeedbackStaysReadable() {
    JsonNode empty = Json.API.createObjectNode();

    List<Violation> violations = validate(empty);

    assertTrue(violations.size() <= 20, "was " + violations.size());
    assertTrue(violations.size() >= 10, "an empty object violates most of the schema");
  }
}
