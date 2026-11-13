package io.holbein.ai.secgateway.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;

import io.holbein.ai.secgateway.schema.CveTriageSchema;
import io.holbein.ai.secgateway.Json;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.JsonNode;

class CveTriageSchemaTest {
  private static final JsonNode SCHEMA =
      Json.API.readTree(Json.API.writeValueAsString(CveTriageSchema.schema()));

  @Test
  void schemaPropertiesMatchRecordComponents() {
    assertComponentsMatch(SCHEMA, CveTriage.class);
    JsonNode props = SCHEMA.get("properties");
    assertComponentsMatch(props.get("affected"), CveTriage.Affected.class);
    assertComponentsMatch(props.get("weakness"), CveTriage.Weakness.class);
    assertComponentsMatch(props.get("severity"), CveTriage.Severity.class);
    assertComponentsMatch(props.get("exploitability"), CveTriage.Exploitability.class);
    assertComponentsMatch(props.get("impact"), CveTriage.Impact.class);
    assertComponentsMatch(props.get("remediation"), CveTriage.Remediation.class);
  }

  @Test
  void enumValuesComeFromTheJavaEnums() {
    JsonNode props = SCHEMA.get("properties");
    assertEquals(
        List.of("BLOCK", "WARN", "ALLOW", "NEEDS_HUMAN_REVIEW"),
        values(props.get("verdict").get("enum")));
    assertEquals(
        List.of("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"),
        values(props.get("severity").get("properties").get("nvd_severity").get("enum")));
    assertEquals(
        CveTriage.ComponentType.values().length,
        values(props.get("affected").get("properties").get("component_type").get("enum")).size());
    assertEquals(
        CveTriage.Mechanism.values().length,
        values(props.get("weakness").get("properties").get("mechanism").get("enum")).size());
  }

  @Test
  void theSchemaHashIsPinned() {
    assertEquals(
        "81f1521f6e417e68",
        Json.sha256(CveTriageSchema.schema()),
        "The output schema changed (or its serialization is not deterministic across JVMs). If the"
            + " change is intended: update this constant and add a dated DECISIONS.md entry; the"
            + " manifest of every run records this value.");
  }

  @Test
  void schemaKeywordsSurviveTheSnakeCaseMapper() {
    assertTrue(SCHEMA.has("additionalProperties"), "additionalProperties was renamed");
    assertNull(SCHEMA.get("additional_properties"));

    JsonNode fixedVersion =
        SCHEMA.get("properties").get("affected").get("properties").get("fixed_version");
    assertTrue(fixedVersion.has("anyOf"), "anyOf was renamed");
    assertEquals("string", fixedVersion.get("anyOf").get(0).get("type").asString());
    assertEquals("null", fixedVersion.get("anyOf").get(1).get("type").asString());
  }

  private static List<String> values(JsonNode array) {
    List<String> out = new ArrayList<>();
    array.forEach(n -> out.add(n.asString()));
    return out;
  }

  private static Object instanceOf(Class<?> record) {
    CveTriage sample = CveTriage.needsHumanReview("CVE-0000-0000", "fixture");
    if (record == CveTriage.class) {
      return sample;
    }
    if (record == CveTriage.Affected.class) {
      return sample.affected();
    }
    if (record == CveTriage.Weakness.class) {
      return sample.weakness();
    }
    if (record == CveTriage.Severity.class) {
      return sample.severity();
    }
    if (record == CveTriage.Exploitability.class) {
      return sample.exploitability();
    }
    if (record == CveTriage.Impact.class) {
      return sample.impact();
    }
    return sample.remediation();
  }

  private static void assertComponentsMatch(JsonNode objectSchema, Class<?> record) {
    List<String> schemaFields = new ArrayList<>();
    objectSchema.get("properties").propertyNames().forEach(schemaFields::add);

    List<String> recordFields = new ArrayList<>();
    Json.API.valueToTree(instanceOf(record)).propertyNames().forEach(recordFields::add);
    recordFields.sort(null);

    assertEquals(
        schemaFields.stream().sorted().toList(), recordFields, record.getSimpleName() + " drifted");
  }

}
