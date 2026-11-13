package io.holbein.ai.secgateway.validation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import io.holbein.ai.secgateway.model.CveInput;
import io.holbein.ai.secgateway.model.CveTriage;
import io.holbein.ai.secgateway.model.CveTriage.AttackVector;
import io.holbein.ai.secgateway.model.CveTriage.ComponentType;
import io.holbein.ai.secgateway.model.CveTriage.ExploitMaturity;
import io.holbein.ai.secgateway.model.CveTriage.ImpactLevel;
import io.holbein.ai.secgateway.model.CveTriage.Mechanism;
import io.holbein.ai.secgateway.model.CveTriage.PrivilegesRequired;
import io.holbein.ai.secgateway.model.CveTriage.SeverityLevel;
import io.holbein.ai.secgateway.validation.Finding.Severity;

/**
 * Checks a schema-valid {@link CveTriage} against the {@link CveInput} the model was given.
 *
 * <p>The oracle is always the input, never the raw NVD record and never an outside source: a
 * field is grounded when the model could have read it from what it was sent. Each check reports
 * PASS, FAIL or UNVERIFIABLE (oracle absent) and carries a HARD or SOFT severity; VALIDATION.md
 * holds the per-field table this class implements.
 */
public final class GroundingValidator {
  private static final Pattern VERSION = Pattern.compile("\\d+(?:\\.\\d+)+");
  private static final int MAX_KEY_REFERENCES = 3;
  private static final List<String> EXPLOIT_WORDS =
      List.of("exploit", "proof of concept", "proof-of-concept", "metasploit", "in the wild");

  /** "no CVSS metrics", "missing CWE ids": a leading negation, the subject, and the rest. */
  private static final Pattern DENIAL =
      Pattern.compile("\\b(no|missing|without|lacks?|absent)\\s+(cvss|cwe|cpe)\\b(.*)$");

  /** Words that may follow the subject of a denial without changing what it denies. */
  private static final Set<String> FILLER =
      Set.of("metric", "metrics", "score", "scores", "data", "base", "vector", "rating",
          "severity", "id", "ids", "identifier", "identifiers", "entry", "entries",
          "configuration", "configurations", "classification", "weakness", "match", "matches",
          "assigned", "published", "provided", "available", "present", "listed", "stated",
          "given", "supplied", "yet", "in", "the", "input", "record", "nvd", "by", "from", "for",
          "this", "cve", "at", "all", "any", "or", "and", "a", "an", "is", "are", "was", "were");

  /** The CWE to mechanism table from the {@code weakness.mechanism} field description. */
  private static final Map<String, Mechanism> CWE_MECHANISM =
      Map.of(
          "CWE-502", Mechanism.DESERIALIZATION,
          "CWE-22", Mechanism.PATH_TRAVERSAL,
          "CWE-79", Mechanism.INJECTION,
          "CWE-89", Mechanism.INJECTION,
          "CWE-119", Mechanism.MEMORY_SAFETY,
          "CWE-120", Mechanism.MEMORY_SAFETY,
          "CWE-125", Mechanism.MEMORY_SAFETY,
          "CWE-787", Mechanism.MEMORY_SAFETY);

  /** The CPE category to component type table from the {@code component_type} description. */
  private static final Map<String, Set<ComponentType>> CPE_COMPONENTS =
      Map.of(
          "application",
          EnumSet.of(
              ComponentType.LIBRARY, ComponentType.APPLICATION, ComponentType.PLUGIN,
              ComponentType.HOSTED_SERVICE),
          "operating_system",
          EnumSet.of(ComponentType.OPERATING_SYSTEM, ComponentType.OS_PACKAGE),
          "hardware",
          EnumSet.of(ComponentType.FIRMWARE));

  private final CveInput in;
  private final CveTriage out;
  private final List<Finding> findings = new ArrayList<>();
  private final boolean v2;
  private final String cvssTag;
  private final Set<String> inputVersions;

  private GroundingValidator(CveInput in, CveTriage out) {
    this.in = in;
    this.out = out;
    this.v2 = in.cvss() != null && "2.0".equals(in.cvss().version());
    this.cvssTag = in.cvss() == null ? "" : " (CVSS " + in.cvss().version() + ")";
    this.inputVersions = versions(inputText());
  }

  public static GroundingReport validate(CveInput input, CveTriage triage) {
    GroundingValidator v = new GroundingValidator(input, triage);
    v.identity();
    v.affected();
    v.weakness();
    v.severity();
    v.exploitability();
    v.impact();
    v.references();
    v.dataGaps();
    Invariants.check(input, triage, v.findings);
    return new GroundingReport(List.copyOf(v.findings));
  }

  private void identity() {
    check("cve_id", Severity.HARD, Objects.equals(in.cveId(), out.cveId()),
        "copied from the input", "was " + quote(out.cveId()) + ", input is " + quote(in.cveId()));
  }

  private void affected() {
    CveTriage.Affected a = out.affected();
    Set<String> vendors = cpeSegment(3);
    Set<String> products = cpeSegment(4);

    if (vendors.isEmpty()) {
      unverifiable("affected.vendor", "input has no CPE configurations");
      unverifiable("affected.product", "input has no CPE configurations");
    } else {
      nameMatches("affected.vendor", a.vendor(), vendors);
      nameMatches("affected.product", a.product(), products);
    }

    if (in.cpeCategories().isEmpty()) {
      unverifiable("affected.component_type", "input has no cpe_categories");
    } else {
      Set<ComponentType> allowed = EnumSet.noneOf(ComponentType.class);
      for (String category : in.cpeCategories()) {
        allowed.addAll(CPE_COMPONENTS.getOrDefault(category, Set.of()));
      }
      check("affected.component_type", Severity.SOFT, allowed.contains(a.componentType()),
          "consistent with cpe_categories " + in.cpeCategories(),
          "was " + a.componentType() + ", cpe_categories " + in.cpeCategories() + " allow "
              + allowed);
    }

    Set<String> claimed = versions(a.vulnerableVersions());
    if (claimed.isEmpty()) {
      unverifiable("affected.vulnerable_versions", "no version numbers to check (prose only)");
    } else {
      Set<String> missing = minus(claimed, inputVersions);
      check("affected.vulnerable_versions", Severity.SOFT, missing.isEmpty(),
          "every version number appears in the input",
          "version numbers not in the input: " + missing);
    }

    if (a.fixedVersion() == null) {
      findings.add(Finding.pass("affected.fixed_version", "null: no fix claimed"));
      return;
    }
    Set<String> fixed = versions(a.fixedVersion());
    if (fixed.isEmpty()) {
      unverifiable("affected.fixed_version", "no version number in " + quote(a.fixedVersion()));
    } else {
      Set<String> missing = minus(fixed, inputVersions);
      check("affected.fixed_version", Severity.HARD, missing.isEmpty(),
          "version number appears in the input",
          quote(a.fixedVersion()) + " names version(s) absent from the input: " + missing
              + " (never guess a version number)");
    }
  }

  private void nameMatches(String path, String value, Set<String> cpeNames) {
    if (value == null) {
      findings.add(Finding.fail(path, Severity.SOFT, "was null, but CPE names " + cpeNames));
      return;
    }
    String normalized = normalize(value);
    boolean hit = cpeNames.stream().map(GroundingValidator::normalize)
        .anyMatch(n -> !n.isEmpty() && (normalized.contains(n) || n.contains(normalized)));
    check(path, Severity.SOFT, hit, "matches CPE " + cpeNames,
        "was " + quote(value) + ", CPE names " + cpeNames);
  }

  private void weakness() {
    CveTriage.Weakness w = out.weakness();
    Set<String> extra = minus(new LinkedHashSet<>(w.cweIds()), in.cweIds());
    check("weakness.cwe_ids", Severity.HARD, extra.isEmpty(),
        "subset of the input's " + in.cweIds(),
        "introduces CWE ids not in the input: " + extra + " (input has " + in.cweIds() + ")");

    Set<Mechanism> mapped = EnumSet.noneOf(Mechanism.class);
    for (String cwe : in.cweIds()) {
      Mechanism m = CWE_MECHANISM.get(cwe);
      if (m != null) {
        mapped.add(m);
      }
    }
    if (mapped.isEmpty()) {
      unverifiable("weakness.mechanism",
          "no CWE in " + in.cweIds() + " has a fixed mechanism; judgement field");
    } else {
      check("weakness.mechanism", Severity.HARD, mapped.contains(w.mechanism()),
          "follows the CWE mapping " + mapped,
          "was " + w.mechanism() + ", but " + in.cweIds() + " maps to " + mapped);
    }
  }

  private void severity() {
    CveTriage.Severity s = out.severity();
    CveInput.Cvss c = in.cvss();
    if (c == null) {
      check("severity.nvd_base_score", Severity.HARD, s.nvdBaseScore() == null,
          "null, input has no CVSS", "was " + s.nvdBaseScore() + ", input has no CVSS metrics");
      check("severity.nvd_severity", Severity.HARD, s.nvdSeverity() == SeverityLevel.UNKNOWN,
          "UNKNOWN, input has no CVSS", "was " + s.nvdSeverity() + ", input has no CVSS metrics");
      return;
    }
    check("severity.nvd_base_score", Severity.HARD,
        s.nvdBaseScore() != null && c.baseScore() != null
            && Double.compare(s.nvdBaseScore(), c.baseScore()) == 0,
        "copied verbatim (" + c.baseScore() + ")",
        "was " + s.nvdBaseScore() + ", input says " + c.baseScore());
    if (c.baseSeverity() == null) {
      unverifiable("severity.nvd_severity", "input CVSS carries no baseSeverity");
    } else {
      check("severity.nvd_severity", Severity.HARD,
          s.nvdSeverity().name().equalsIgnoreCase(c.baseSeverity()),
          "copied verbatim (" + c.baseSeverity() + ")",
          "was " + s.nvdSeverity() + ", input says " + c.baseSeverity());
    }
  }

  private void exploitability() {
    CveTriage.Exploitability e = out.exploitability();
    CveInput.Cvss c = in.cvss();

    if (c == null || c.attackVector() == null) {
      unverifiable("exploitability.attack_vector", "input has no CVSS vector");
    } else {
      vectorCheck("exploitability.attack_vector", Severity.HARD, e.attackVector(),
          attackVector(c.attackVector()), c.attackVector());
    }

    if (c == null || c.privilegesRequired() == null) {
      unverifiable("exploitability.privileges_required", "input has no CVSS vector");
    } else {
      vectorCheck("exploitability.privileges_required", v2 ? Severity.SOFT : Severity.HARD,
          e.privilegesRequired(), privileges(c.privilegesRequired()), c.privilegesRequired());
    }

    if (c == null || c.userInteraction() == null) {
      unverifiable("exploitability.user_interaction_required",
          c == null ? "input has no CVSS vector" : "CVSS" + cvssTag + " states no UI metric");
    } else {
      Boolean expected = !"NONE".equals(c.userInteraction());
      check("exploitability.user_interaction_required", v2 ? Severity.SOFT : Severity.HARD,
          expected.equals(e.userInteractionRequired()),
          "matches UI=" + c.userInteraction() + cvssTag,
          "was " + e.userInteractionRequired() + ", vector says UI=" + c.userInteraction()
              + cvssTag);
    }

    ExploitMaturity m = e.exploitMaturity();
    String path = "exploitability.exploit_maturity";
    if (Boolean.TRUE.equals(in.knownExploited())) {
      check(path, Severity.HARD, m == ExploitMaturity.ACTIVELY_EXPLOITED,
          "ACTIVELY_EXPLOITED, input is KEV-listed",
          "was " + m + ", but the input is KEV-listed (known_exploited=true)");
    } else if (hasReferenceTag("Exploit")) {
      check(path, Severity.SOFT, m.ordinal() >= ExploitMaturity.PROOF_OF_CONCEPT.ordinal(),
          "at least PROOF_OF_CONCEPT, input has an Exploit reference",
          "was " + m + ", but a reference carries the Exploit tag");
    } else if (descriptionMentionsExploitation()) {
      unverifiable(path, "description mentions exploitation; no structured evidence to check");
    } else {
      check(path, Severity.SOFT, m.ordinal() <= ExploitMaturity.UNPROVEN.ordinal(),
          "no exploit evidence in the input, maturity not raised",
          "was " + m + ", but the input carries no Exploit tag, KEV listing or mention");
    }
  }

  private void impact() {
    CveInput.Cvss c = in.cvss();
    CveTriage.Impact i = out.impact();
    impactCheck("impact.confidentiality", i.confidentiality(),
        c == null ? null : c.confidentialityImpact());
    impactCheck("impact.integrity", i.integrity(), c == null ? null : c.integrityImpact());
    impactCheck("impact.availability", i.availability(), c == null ? null : c.availabilityImpact());
  }

  private void impactCheck(String path, ImpactLevel actual, String nvd) {
    if (nvd == null) {
      unverifiable(path, "input has no CVSS vector");
    } else {
      vectorCheck(path, v2 ? Severity.SOFT : Severity.HARD, actual, impact(nvd), nvd);
    }
  }

  private <E extends Enum<E>> void vectorCheck(
      String path, Severity severity, E actual, E expected, String nvd) {
    if (expected == null) {
      unverifiable(path, "unrecognised CVSS value " + quote(nvd) + cvssTag);
      return;
    }
    check(path, severity, expected == actual, "matches " + nvd + cvssTag,
        "was " + actual + ", vector says " + nvd + " = " + expected + cvssTag);
  }

  private void references() {
    Set<String> urls = new LinkedHashSet<>();
    in.references().forEach(r -> urls.add(r.url()));
    Set<String> extra = minus(new LinkedHashSet<>(out.keyReferences()), urls);
    check("key_references", Severity.HARD, extra.isEmpty(),
        "subset of the input's " + urls.size() + " URLs", "URLs not in the input: " + extra);
    check("key_references.size", Severity.HARD, out.keyReferences().size() <= MAX_KEY_REFERENCES,
        "at most " + MAX_KEY_REFERENCES,
        out.keyReferences().size() + " URLs, at most " + MAX_KEY_REFERENCES + " allowed");
  }

  /**
   * A gap that denies something the input contains ("no CVSS metrics" next to a CVSS 3.1 block)
   * is a reading error. Only a leading negation followed by nothing but filler counts: "no CVSS
   * v3 metrics" and "no affected version boundaries (CPE wildcard only)" are legitimate gaps.
   */
  private void dataGaps() {
    List<String> contradictions = new ArrayList<>();
    for (String gap : out.dataGaps()) {
      Matcher m = DENIAL.matcher(gap.toLowerCase(Locale.ROOT));
      if (!m.find()) {
        continue;
      }
      List<String> tail =
          Arrays.stream(m.group(3).replaceAll("[^a-z0-9. ]", " ").trim().split("\\s+"))
              .map(w -> w.replaceAll("^\\.+|\\.+$", ""))
              .toList();
      boolean versionQualified = tail.stream().anyMatch(w -> w.matches("v?\\d(\\.\\d)?"));
      boolean aboutSomethingElse = !tail.stream().allMatch(w -> w.isEmpty() || FILLER.contains(w));
      if (versionQualified || aboutSomethingElse) {
        continue;
      }
      switch (m.group(2)) {
        case "cvss" -> {
          if (in.cvss() != null) {
            contradictions.add(quote(gap) + " but input has CVSS " + in.cvss().version());
          }
        }
        case "cwe" -> {
          if (!in.cweIds().isEmpty()) {
            contradictions.add(quote(gap) + " but input has " + in.cweIds());
          }
        }
        default -> {
          if (!in.cpeCategories().isEmpty()) {
            contradictions.add(
                quote(gap) + " but input has cpe_categories " + in.cpeCategories());
          }
        }
      }
    }
    check("data_gaps", Severity.SOFT, contradictions.isEmpty(),
        out.dataGaps().isEmpty() ? "empty" : "no gap denies something the input contains",
        "gap(s) deny what the input contains: " + contradictions);
  }

  private Set<String> cpeSegment(int index) {
    Set<String> names = new LinkedHashSet<>();
    for (CveInput.AffectedRange range : in.affected()) {
      if (range.criteria() == null) {
        continue;
      }
      String[] parts = range.criteria().split(":");
      if (parts.length > index && !parts[index].equals("*")) {
        names.add(parts[index]);
      }
    }
    return names;
  }

  /** Everything in the input a version number could legitimately be read from. */
  private String inputText() {
    StringBuilder text = new StringBuilder();
    if (in.description() != null) {
      text.append(in.description()).append(' ');
    }
    for (CveInput.AffectedRange r : in.affected()) {
      for (String part : List.of(
          String.valueOf(r.startIncluding()), String.valueOf(r.startExcluding()),
          String.valueOf(r.endIncluding()), String.valueOf(r.endExcluding()),
          String.valueOf(r.criteria()))) {
        text.append(part).append(' ');
      }
    }
    for (CveInput.Reference r : in.references()) {
      text.append(r.url()).append(' ');
    }
    return text.toString();
  }

  private boolean hasReferenceTag(String tag) {
    return in.references().stream().anyMatch(r -> r.tags() != null && r.tags().contains(tag));
  }

  private boolean descriptionMentionsExploitation() {
    if (in.description() == null) {
      return false;
    }
    String d = in.description().toLowerCase(Locale.ROOT);
    return EXPLOIT_WORDS.stream().anyMatch(d::contains);
  }

  private static Set<String> versions(String text) {
    Set<String> found = new LinkedHashSet<>();
    if (text != null) {
      Matcher m = VERSION.matcher(text);
      while (m.find()) {
        found.add(m.group());
      }
    }
    return found;
  }

  private static Set<String> minus(Set<String> a, Collection<String> b) {
    Set<String> result = new LinkedHashSet<>(a);
    result.removeAll(b);
    return result;
  }

  private static String normalize(String name) {
    return name.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
  }

  private static AttackVector attackVector(String nvd) {
    return switch (nvd) {
      case "NETWORK" -> AttackVector.NETWORK;
      case "ADJACENT_NETWORK", "ADJACENT" -> AttackVector.ADJACENT;
      case "LOCAL" -> AttackVector.LOCAL;
      case "PHYSICAL" -> AttackVector.PHYSICAL;
      default -> null;
    };
  }

  /** v3/v4 use NONE/LOW/HIGH; v2 authentication uses NONE/SINGLE/MULTIPLE, mapped by convention. */
  private static PrivilegesRequired privileges(String nvd) {
    return switch (nvd) {
      case "NONE" -> PrivilegesRequired.NONE;
      case "LOW", "SINGLE" -> PrivilegesRequired.LOW;
      case "HIGH", "MULTIPLE" -> PrivilegesRequired.HIGH;
      default -> null;
    };
  }

  /** v3/v4 use NONE/LOW/HIGH; v2 uses NONE/PARTIAL/COMPLETE, mapped by convention. */
  private static ImpactLevel impact(String nvd) {
    return switch (nvd) {
      case "NONE" -> ImpactLevel.NONE;
      case "LOW", "PARTIAL" -> ImpactLevel.LOW;
      case "HIGH", "COMPLETE" -> ImpactLevel.HIGH;
      default -> null;
    };
  }

  private void check(String path, Severity severity, boolean ok, String passed, String failed) {
    findings.add(ok ? Finding.pass(path, passed) : Finding.fail(path, severity, failed));
  }

  private void unverifiable(String path, String message) {
    findings.add(Finding.unverifiable(path, message));
  }

  private static String quote(String s) {
    return s == null ? "null" : "\"" + s + "\"";
  }
}
