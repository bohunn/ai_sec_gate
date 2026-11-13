package io.holbein.ai.secgateway.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.util.List;

import io.holbein.ai.secgateway.Json;
import io.holbein.ai.secgateway.nvd.NvdCveResponse;
import org.junit.jupiter.api.Test;

class CveInputTest {
  private static CveInput sample() {
    try (InputStream in = CveInputTest.class.getResourceAsStream("/nvd-cve-sample.json")) {
      return CveInput.from(Json.NVD.readValue(in, NvdCveResponse.class).vulnerabilities().get(0).cve());
    } catch (java.io.IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
  }

  private static NvdCveResponse.Cve cveWithDescription(String id, String description) {
    return new NvdCveResponse.Cve(
        id, null, "Analyzed", null,
        List.of(new NvdCveResponse.LangValue("en", description)),
        null, null, null, null, null);
  }

  private static NvdCveResponse.Cve kevListed(String id) {
    return new NvdCveResponse.Cve(
        id, null, "Analyzed", null,
        List.of(new NvdCveResponse.LangValue("en", "Exploited in the wild.")),
        null, "2026-01-26", null, null, null);
  }

  private static NvdCveResponse.Cve v2Only(String id, Boolean userInteractionRequired) {
    NvdCveResponse.CvssDataV2 data =
        new NvdCveResponse.CvssDataV2(
            "2.0", "AV:N/AC:M/Au:N/C:P/I:P/A:P", 6.8, "NETWORK", "MEDIUM", "NONE",
            "PARTIAL", "PARTIAL", "PARTIAL");
    NvdCveResponse.Metrics metrics =
        new NvdCveResponse.Metrics(
            null, null, null,
            List.of(new NvdCveResponse.CvssMetricV2(data, "MEDIUM", false, userInteractionRequired)));
    return new NvdCveResponse.Cve(
        id, null, "Analyzed", null,
        List.of(new NvdCveResponse.LangValue("en", "Old bug.")),
        metrics, null, null, null, null);
  }

  @Test
  void projectsTheFieldsTheModelNeeds() {
    CveInput input = sample();

    assertEquals("CVE-2019-1010218", input.cveId());
    assertEquals(List.of("CWE-120", "CWE-787"), input.cweIds());
    assertTrue(input.description().startsWith("Cherokee Webserver"));

    assertEquals("3.1", input.cvss().version());
    assertEquals(7.5, input.cvss().baseScore());
    assertEquals("HIGH", input.cvss().baseSeverity());
    assertEquals("NETWORK", input.cvss().attackVector());

    assertEquals(List.of("application"), input.cpeCategories());
    assertEquals(List.of(), input.tags(), "this fixture carries no NVD tags");
    assertEquals(false, input.knownExploited(), "this fixture is not KEV-listed");
    assertNull(input.kevDateAdded());

    assertEquals(1, input.affected().size());
    assertEquals("1.2.103", input.affected().get(0).endIncluding());

    assertEquals(1, input.references().size(), "duplicate reference URLs must collapse");
    assertEquals("https://i.imgur.com/PWCCyir.png", input.references().get(0).url());
  }

  @Test
  void dropsFieldsThatAreNotPartOfTheContract() {
    String json = Json.API.writeValueAsString(sample());

    assertFalse(json.contains("matchCriteriaId"), "CPE match ids are noise");
    assertFalse(json.contains("match_criteria_id"), "CPE match ids are noise");
    assertFalse(json.contains("sourceIdentifier"), "reporter identity is not triage input");
    assertFalse(json.contains("source_identifier"), "reporter identity is not triage input");
    assertTrue(json.contains("\"cve_id\""), "request mapper emits snake_case");
  }

  @Test
  void stripsControlCharactersAndCollapsesWhitespace() {
    String noisy = "line" + (char) 0 + "one" + (char) 10 + "line" + (char) 9 + (char) 9 + "two   spaced";

    assertEquals("line one line two spaced", CveInput.from(cveWithDescription("CVE-0-0", noisy)).description());
  }

  @Test
  void capsDescriptionLength() {
    String huge = "A".repeat(9000);

    String description = CveInput.from(cveWithDescription("CVE-0-1", huge)).description();

    assertTrue(description.length() < 4100, "description must be bounded, was " + description.length());
    assertTrue(description.endsWith("[truncated]"));
  }

  @Test
  void carriesTheKevListingSoTheModelAndTheValidatorSeeTheSameEvidence() {
    CveInput input = CveInput.from(kevListed("CVE-0-3"));

    assertEquals(true, input.knownExploited());
    assertEquals("2026-01-26", input.kevDateAdded());
    assertTrue(Json.API.writeValueAsString(input).contains("\"known_exploited\":true"));
  }

  @Test
  void mapsTheV2UserInteractionFlagOntoTheSharedCvssShape() {
    assertEquals("REQUIRED", CveInput.from(v2Only("CVE-0-4", true)).cvss().userInteraction());
    assertEquals("NONE", CveInput.from(v2Only("CVE-0-5", false)).cvss().userInteraction());
    assertNull(CveInput.from(v2Only("CVE-0-6", null)).cvss().userInteraction(),
        "v2 without the flag states nothing about user interaction");
    assertEquals("NONE", CveInput.from(v2Only("CVE-0-4", true)).cvss().privilegesRequired(),
        "v2 authentication rides in the privilegesRequired slot");
  }

  @Test
  void survivesACveWithNoMetricsOrConfigurations() {
    CveInput input = CveInput.from(cveWithDescription("CVE-0-2", "Not yet analyzed."));

    assertNull(input.cvss());
    assertEquals(List.of(), input.cweIds());
    assertEquals(List.of(), input.cpeCategories(), "no configurations means no grounded category");
    assertEquals(List.of(), input.affected());
    assertEquals(List.of(), input.references());
  }
}
