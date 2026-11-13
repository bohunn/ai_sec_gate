package io.holbein.ai.secgateway.model;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonInclude;

import io.holbein.ai.secgateway.nvd.NvdCveResponse;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record CveInput(
    String cveId,
    String publishedDate,
    String vulnStatus,
    Boolean knownExploited,
    String kevDateAdded,
    List<String> tags,
    String description,
    List<String> cweIds,
    Cvss cvss,
    List<String> cpeCategories,
    List<AffectedRange> affected,
    List<Reference> references) {
  private static final int MAX_DESCRIPTION_CHARS = 4000;
  private static final int MAX_AFFECTED_RANGES = 20;
  private static final int MAX_REFERENCES = 10;

  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record Cvss(
      String version,
      String vectorString,
      Double baseScore,
      String baseSeverity,
      String attackVector,
      String attackComplexity,
      String privilegesRequired,
      String userInteraction,
      String confidentialityImpact,
      String integrityImpact,
      String availabilityImpact) {
  }

  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record AffectedRange(
      String criteria,
      String startIncluding,
      String startExcluding,
      String endIncluding,
      String endExcluding) {
  }

  public record Reference(String url, List<String> tags) {
  }

  /**
   * The shape of the input as the model sees it: a sample with every field populated, plus the
   * caps. Its serialization changes exactly when a field, a nested field or a cap changes, so its
   * hash is the input-shape element of a run's comparability key (DECISIONS.md, 2026-11-13).
   */
  public static Map<String, Object> shape() {
    CveInput sample =
        new CveInput(
            "CVE-0000-0000", "2000-01-01", "Analyzed", true, "2000-01-02", List.of("tag"),
            "description", List.of("CWE-0"),
            new Cvss("3.1", "CVSS:3.1/", 0.0, "LOW", "NETWORK", "LOW", "NONE", "NONE", "NONE",
                "NONE", "NONE"),
            List.of("application"),
            List.of(new AffectedRange("cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", "1", "1", "1", "1")),
            List.of(new Reference("https://example.invalid/", List.of("tag"))));
    // Insertion-ordered maps only: Map.of iterates in a per-JVM random order, which would make
    // the hash differ between processes.
    Map<String, Object> caps = new LinkedHashMap<>();
    caps.put("max_description_chars", MAX_DESCRIPTION_CHARS);
    caps.put("max_affected_ranges", MAX_AFFECTED_RANGES);
    caps.put("max_references", MAX_REFERENCES);
    Map<String, Object> shape = new LinkedHashMap<>();
    shape.put("fields", sample);
    shape.put("caps", caps);
    return shape;
  }

  public static CveInput from(NvdCveResponse.Cve cve) {
    return new CveInput(
        cve.id(),
        cve.published() == null ? null : cve.published().toLocalDate().toString(),
        cve.vulnStatus(),
        cve.cisaExploitAdd() != null,
        cve.cisaExploitAdd(),
        tags(cve),
        englishDescription(cve),
        cweIds(cve),
        cvss(cve.metrics()),
        cpeCategories(cve),
        affectedRanges(cve),
        references(cve));
  }

  private static List<String> tags(NvdCveResponse.Cve cve) {
    if (cve.cveTags() == null) {
      return List.of();
    }
    Set<String> tags = new LinkedHashSet<>();
    for (NvdCveResponse.CveTag entry : cve.cveTags()) {
      if (entry.tags() != null) {
        tags.addAll(entry.tags());
      }
    }
    return List.copyOf(tags);
  }

  private static String englishDescription(NvdCveResponse.Cve cve) {
    if (cve.descriptions() == null) {
      return null;
    }
    return cve.descriptions().stream()
        .filter(d -> "en".equalsIgnoreCase(d.lang()))
        .map(NvdCveResponse.LangValue::value)
        .findFirst()
        .map(CveInput::sanitize)
        .orElse(null);
  }

  private static List<String> cweIds(NvdCveResponse.Cve cve) {
    Set<String> ids = new LinkedHashSet<>();
    if (cve.weaknesses() != null) {
      for (NvdCveResponse.Weakness weakness : cve.weaknesses()) {
        if (weakness.description() == null) {
          continue;
        }
        for (NvdCveResponse.LangValue value : weakness.description()) {
          String cwe = value.value();
          if (cwe != null && cwe.startsWith("CWE-")) {
            ids.add(cwe);
          }
        }
      }
    }
    return List.copyOf(ids);
  }

  private static Cvss cvss(NvdCveResponse.Metrics metrics) {
    if (metrics == null) {
      return null;
    }
    Cvss v3 = fromV3(metrics.cvssMetricV31());
    if (v3 != null) {
      return v3;
    }
    v3 = fromV3(metrics.cvssMetricV30());
    if (v3 != null) {
      return v3;
    }
    if (hasEntry(metrics.cvssMetricV40())) {
      NvdCveResponse.CvssDataV40 d = metrics.cvssMetricV40().get(0).cvssData();
      return new Cvss(
          d.version(), d.vectorString(), d.baseScore(), d.baseSeverity(),
          d.attackVector(), d.attackComplexity(), d.privilegesRequired(), d.userInteraction(),
          d.vulnConfidentialityImpact(), d.vulnIntegrityImpact(), d.vulnAvailabilityImpact());
    }
    if (hasEntry(metrics.cvssMetricV2())) {
      NvdCveResponse.CvssMetricV2 m = metrics.cvssMetricV2().get(0);
      NvdCveResponse.CvssDataV2 d = m.cvssData();
      String userInteraction =
          m.userInteractionRequired() == null
              ? null
              : m.userInteractionRequired() ? "REQUIRED" : "NONE";
      return new Cvss(
          d.version(), d.vectorString(), d.baseScore(), m.baseSeverity(),
          d.accessVector(), d.accessComplexity(), d.authentication(), userInteraction,
          d.confidentialityImpact(), d.integrityImpact(), d.availabilityImpact());
    }
    return null;
  }

  private static Cvss fromV3(List<NvdCveResponse.CvssMetricV3> metrics) {
    if (!hasEntry(metrics)) {
      return null;
    }
    NvdCveResponse.CvssDataV3 d = metrics.get(0).cvssData();
    return new Cvss(
        d.version(), d.vectorString(), d.baseScore(), d.baseSeverity(),
        d.attackVector(), d.attackComplexity(), d.privilegesRequired(), d.userInteraction(),
        d.confidentialityImpact(), d.integrityImpact(), d.availabilityImpact());
  }

  private static boolean hasEntry(List<?> list) {
    return list != null && !list.isEmpty();
  }

  private static List<String> cpeCategories(NvdCveResponse.Cve cve) {
    Set<String> categories = new LinkedHashSet<>();
    for (NvdCveResponse.CpeMatch match : vulnerableMatches(cve)) {
      String category = cpeCategory(match.criteria());
      if (category != null) {
        categories.add(category);
      }
    }
    return List.copyOf(categories);
  }

  private static String cpeCategory(String criteria) {
    if (criteria == null) {
      return null;
    }
    String[] segments = criteria.split(":");
    if (segments.length < 3) {
      return null;
    }
    return switch (segments[2]) {
      case "a" -> "application";
      case "o" -> "operating_system";
      case "h" -> "hardware";
      default -> null;
    };
  }

  private static List<NvdCveResponse.CpeMatch> vulnerableMatches(NvdCveResponse.Cve cve) {
    List<NvdCveResponse.CpeMatch> matches = new ArrayList<>();
    if (cve.configurations() == null) {
      return matches;
    }
    for (NvdCveResponse.Configuration configuration : cve.configurations()) {
      if (configuration.nodes() == null) {
        continue;
      }
      for (NvdCveResponse.Node node : configuration.nodes()) {
        if (node.cpeMatch() == null) {
          continue;
        }
        for (NvdCveResponse.CpeMatch match : node.cpeMatch()) {
          if (match.vulnerable()) {
            matches.add(match);
          }
        }
      }
    }
    return matches;
  }

  private static List<AffectedRange> affectedRanges(NvdCveResponse.Cve cve) {
    List<AffectedRange> ranges = new ArrayList<>();
    for (NvdCveResponse.CpeMatch match : vulnerableMatches(cve)) {
      if (ranges.size() >= MAX_AFFECTED_RANGES) {
        break;
      }
      ranges.add(
          new AffectedRange(
              match.criteria(),
              match.versionStartIncluding(),
              match.versionStartExcluding(),
              match.versionEndIncluding(),
              match.versionEndExcluding()));
    }
    return List.copyOf(ranges);
  }

  private static List<Reference> references(NvdCveResponse.Cve cve) {
    if (cve.references() == null) {
      return List.of();
    }
    Set<String> seen = new LinkedHashSet<>();
    List<Reference> references = new ArrayList<>();
    for (NvdCveResponse.Reference reference : cve.references()) {
      if (reference.url() == null || !seen.add(reference.url())) {
        continue;
      }
      if (references.size() >= MAX_REFERENCES) {
        break;
      }
      references.add(
          new Reference(
              sanitize(reference.url()), reference.tags() == null ? List.of() : reference.tags()));
    }
    return List.copyOf(references);
  }

  private static String sanitize(String raw) {
    String cleaned = raw.replaceAll("[\\p{Cntrl}]+", " ").replaceAll("\\s{2,}", " ").trim();
    return cleaned.length() <= MAX_DESCRIPTION_CHARS
        ? cleaned
        : cleaned.substring(0, MAX_DESCRIPTION_CHARS) + " [truncated]";
  }
}
