package io.holbein.ai.secgateway.nvd;

import java.time.LocalDateTime;
import java.util.List;

public record NvdCveResponse(
    int totalResults,
    String format,
    LocalDateTime timestamp,
    List<VulnerabilityItem> vulnerabilities) {
  public record VulnerabilityItem(Cve cve) {}

  public record Cve(
      String id,
      LocalDateTime published,
      String vulnStatus,
      List<CveTag> cveTags,
      List<LangValue> descriptions,
      Metrics metrics,
      List<Weakness> weaknesses,
      List<Configuration> configurations,
      List<Reference> references) {}

  public record CveTag(List<String> tags) {}

  public record LangValue(String lang, String value) {}

  public record Metrics(
      List<CvssMetricV40> cvssMetricV40,
      List<CvssMetricV3> cvssMetricV31,
      List<CvssMetricV3> cvssMetricV30,
      List<CvssMetricV2> cvssMetricV2) {}

  public record CvssMetricV40(CvssDataV40 cvssData) {}

  public record CvssDataV40(
      String version,
      String vectorString,
      double baseScore,
      String baseSeverity,
      String attackVector,
      String attackComplexity,
      String privilegesRequired,
      String userInteraction,
      String vulnConfidentialityImpact,
      String vulnIntegrityImpact,
      String vulnAvailabilityImpact) {}

  public record CvssMetricV3(CvssDataV3 cvssData) {}

  public record CvssDataV3(
      String version,
      String vectorString,
      double baseScore,
      String baseSeverity,
      String attackVector,
      String attackComplexity,
      String privilegesRequired,
      String userInteraction,
      String confidentialityImpact,
      String integrityImpact,
      String availabilityImpact) {}

  public record CvssMetricV2(CvssDataV2 cvssData, String baseSeverity, Boolean acInsufInfo) {}

  public record CvssDataV2(
      String version,
      String vectorString,
      double baseScore,
      String accessVector,
      String accessComplexity,
      String authentication,
      String confidentialityImpact,
      String integrityImpact,
      String availabilityImpact) {}

  public record Weakness(List<LangValue> description) {}

  public record Configuration(List<Node> nodes) {}

  public record Node(List<CpeMatch> cpeMatch) {}

  public record CpeMatch(
      boolean vulnerable,
      String criteria,
      String versionStartIncluding,
      String versionStartExcluding,
      String versionEndIncluding,
      String versionEndExcluding) {}

  public record Reference(String url, List<String> tags) {}
}
