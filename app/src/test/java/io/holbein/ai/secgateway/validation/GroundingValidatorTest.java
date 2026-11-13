package io.holbein.ai.secgateway.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.function.Consumer;

import io.holbein.ai.secgateway.Json;
import io.holbein.ai.secgateway.model.CveInput;
import io.holbein.ai.secgateway.model.CveTriage;
import io.holbein.ai.secgateway.validation.Finding.Severity;
import io.holbein.ai.secgateway.validation.Finding.Status;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.node.ObjectNode;

/**
 * The fixture mirrors CVE-2024-28088 (LangChain path traversal) as the model sees it: CVSS 3.1,
 * two CWEs, one CPE range, one reference. {@link #grounded()} is an output that agrees with it
 * on every checkable field; each test perturbs one field and asserts the finding.
 */
class GroundingValidatorTest {
  private static final CveInput.Cvss V31 =
      new CveInput.Cvss("3.1", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", 8.1, "HIGH",
          "NETWORK", "LOW", "LOW", "NONE", "HIGH", "HIGH", "NONE");
  private static final CveInput.Cvss V2 =
      new CveInput.Cvss("2.0", "AV:N/AC:M/Au:N/C:P/I:P/A:P", 6.8, "MEDIUM",
          "NETWORK", "MEDIUM", "NONE", null, "PARTIAL", "PARTIAL", "PARTIAL");
  private static final String PR_URL = "https://github.com/langchain-ai/langchain/pull/18600";

  private static CveInput input(CveInput.Cvss cvss, boolean kev, String status) {
    return new CveInput(
        "CVE-2024-28088", "2024-03-04", status, kev, kev ? "2026-01-26" : null, List.of(),
        "LangChain through 0.1.10 allows ../ directory traversal in load_chain.",
        List.of("CWE-22", "CWE-31"),
        cvss,
        List.of("application"),
        List.of(new CveInput.AffectedRange(
            "cpe:2.3:a:langchain:langchain:*:*:*:*:*:*:*:*", null, null, null, "0.1.12")),
        List.of(new CveInput.Reference(PR_URL, List.of("Exploit", "Patch"))));
  }

  private static final CveInput INPUT = input(V31, false, "Analyzed");

  private static CveTriage grounded() {
    return new CveTriage(
        "CVE-2024-28088",
        "An attacker who controls the chain path can make the app load a hostile config.",
        new CveTriage.Affected("langchain-ai", "LangChain", CveTriage.ComponentType.LIBRARY,
            "< 0.1.12", "0.1.12"),
        new CveTriage.Weakness(CveTriage.Mechanism.PATH_TRAVERSAL, List.of("CWE-22")),
        new CveTriage.Severity(8.1, CveTriage.SeverityLevel.HIGH, CveTriage.SeverityLevel.HIGH,
            "NVD's HIGH is a fair reflection of a low-privilege network RCE."),
        new CveTriage.Exploitability(CveTriage.AttackVector.NETWORK,
            CveTriage.PrivilegesRequired.LOW, false, CveTriage.ExploitMaturity.PROOF_OF_CONCEPT,
            CveTriage.Likelihood.MEDIUM),
        new CveTriage.Impact(CveTriage.ImpactLevel.HIGH, CveTriage.ImpactLevel.HIGH,
            CveTriage.ImpactLevel.NONE, "Attacker runs code in the application process."),
        new CveTriage.Remediation(CveTriage.RemediationAction.UPGRADE,
            "Upgrade langchain to 0.1.12 or later.", null, CveTriage.Effort.TRIVIAL),
        CveTriage.Verdict.BLOCK, CveTriage.Priority.P1, CveTriage.Confidence.MEDIUM,
        "Network reachable, PoC published, trivial fix available.",
        List.of(), List.of(PR_URL));
  }

  private static CveTriage with(Consumer<ObjectNode> edit) {
    ObjectNode doc = Json.API.valueToTree(grounded());
    edit.accept(doc);
    return Json.API.treeToValue(doc, CveTriage.class);
  }

  private static ObjectNode at(ObjectNode doc, String section) {
    return (ObjectNode) doc.get(section);
  }

  private static Finding finding(GroundingReport report, String path) {
    return report.findings().stream().filter(f -> f.path().equals(path)).findFirst()
        .orElseThrow(() -> new AssertionError("no finding for " + path + " in "
            + report.findings().stream().map(Finding::path).toList()));
  }

  private static void assertFinding(GroundingReport r, String path, Status status, Severity sev) {
    Finding f = finding(r, path);
    assertEquals(status, f.status(), path + ": " + f.message());
    if (status == Status.FAIL) {
      assertEquals(sev, f.severity(), path + " severity");
    }
  }

  @Test
  void anOutputThatAgreesWithTheInputHasNoFailures() {
    GroundingReport report = GroundingValidator.validate(INPUT, grounded());

    assertEquals(List.of(), report.hardFailures(), report.findings().toString());
    assertEquals(List.of(), report.softFailures(), report.findings().toString());
    assertTrue(report.grounded());
    assertTrue(report.passed() >= 20, "most checks have an oracle here: " + report.summary());
  }

  @Test
  void copiedFieldsAreHardChecks() {
    GroundingReport r = GroundingValidator.validate(INPUT, with(d -> {
      d.put("cve_id", "CVE-2024-99999");
      at(d, "severity").put("nvd_base_score", 7.5);
      at(d, "severity").put("nvd_severity", "CRITICAL");
      at(d, "weakness").putArray("cwe_ids").add("CWE-22").add("CWE-502");
      d.putArray("key_references").add(PR_URL).add("https://example.com/not-in-input");
    }));

    assertFinding(r, "cve_id", Status.FAIL, Severity.HARD);
    assertFinding(r, "severity.nvd_base_score", Status.FAIL, Severity.HARD);
    assertFinding(r, "severity.nvd_severity", Status.FAIL, Severity.HARD);
    assertFinding(r, "weakness.cwe_ids", Status.FAIL, Severity.HARD);
    assertFinding(r, "key_references", Status.FAIL, Severity.HARD);
    assertTrue(finding(r, "weakness.cwe_ids").message().contains("CWE-502"), "names the extra");
    assertTrue(finding(r, "key_references").message().contains("example.com"));
  }

  @Test
  void moreThanThreeReferencesIsAHardFailureEvenWhenAllAreFromTheInput() {
    GroundingReport r = GroundingValidator.validate(INPUT, with(d ->
        d.putArray("key_references").add(PR_URL).add(PR_URL + "#a").add(PR_URL + "#b")
            .add(PR_URL + "#c")));

    assertFinding(r, "key_references.size", Status.FAIL, Severity.HARD);
  }

  @Test
  void aFixedVersionAbsentFromTheInputIsTheHallucinationTheProjectWorriesAbout() {
    GroundingReport r = GroundingValidator.validate(INPUT, with(d ->
        at(d, "affected").put("fixed_version", "0.1.29 (langchain-core)")));

    assertFinding(r, "affected.fixed_version", Status.FAIL, Severity.HARD);
    assertTrue(finding(r, "affected.fixed_version").message().contains("0.1.29"));

    GroundingReport fromRange = GroundingValidator.validate(INPUT, grounded());
    assertFinding(fromRange, "affected.fixed_version", Status.PASS, null);

    GroundingReport nothingClaimed = GroundingValidator.validate(INPUT, with(d ->
        at(d, "affected").putNull("fixed_version")));
    assertFinding(nothingClaimed, "affected.fixed_version", Status.PASS, null);
  }

  @Test
  void vectorComponentsAreHardForCvss3() {
    GroundingReport r = GroundingValidator.validate(INPUT, with(d -> {
      at(d, "exploitability").put("attack_vector", "LOCAL");
      at(d, "exploitability").put("privileges_required", "HIGH");
      at(d, "exploitability").put("user_interaction_required", true);
      at(d, "impact").put("confidentiality", "LOW");
    }));

    assertFinding(r, "exploitability.attack_vector", Status.FAIL, Severity.HARD);
    assertFinding(r, "exploitability.privileges_required", Status.FAIL, Severity.HARD);
    assertFinding(r, "exploitability.user_interaction_required", Status.FAIL, Severity.HARD);
    assertFinding(r, "impact.confidentiality", Status.FAIL, Severity.HARD);
    assertFinding(r, "impact.integrity", Status.PASS, null);
  }

  @Test
  void cvss2ImpactAndAuthenticationAreMappedByConventionSoTheyAreSoft() {
    CveInput v2 = input(V2, false, "Analyzed");
    CveTriage partialAsLow = with(d -> {
      at(d, "severity").put("nvd_base_score", 6.8);
      at(d, "severity").put("nvd_severity", "MEDIUM");
      at(d, "severity").put("adjusted_severity", "MEDIUM");
      at(d, "exploitability").put("privileges_required", "NONE");
      at(d, "exploitability").putNull("user_interaction_required");
      at(d, "impact").put("confidentiality", "LOW");
      at(d, "impact").put("integrity", "LOW");
      at(d, "impact").put("availability", "LOW");
      d.put("verdict", "WARN");
      d.put("priority", "P2");
    });

    GroundingReport agree = GroundingValidator.validate(v2, partialAsLow);
    assertFinding(agree, "impact.confidentiality", Status.PASS, null);
    assertFinding(agree, "exploitability.user_interaction_required", Status.UNVERIFIABLE, null);
    assertFinding(agree, "exploitability.attack_vector", Status.PASS, null);

    GroundingReport disagree = GroundingValidator.validate(v2, with(d -> {
      at(d, "severity").put("nvd_base_score", 6.8);
      at(d, "severity").put("nvd_severity", "MEDIUM");
      at(d, "severity").put("adjusted_severity", "MEDIUM");
      at(d, "impact").put("confidentiality", "HIGH");
      at(d, "exploitability").put("privileges_required", "HIGH");
    }));
    assertFinding(disagree, "impact.confidentiality", Status.FAIL, Severity.SOFT);
    assertFinding(disagree, "exploitability.privileges_required", Status.FAIL, Severity.SOFT);
  }

  @Test
  void withoutCvssTheCopiesMustBeEmptyAndTheVectorChecksAreUnverifiableNotSkipped() {
    CveInput sparse = input(null, false, "Awaiting Analysis");

    GroundingReport honest = GroundingValidator.validate(sparse, with(d -> {
      at(d, "severity").putNull("nvd_base_score");
      at(d, "severity").put("nvd_severity", "UNKNOWN");
      at(d, "severity").put("adjusted_severity", "UNKNOWN");
    }));
    assertFinding(honest, "severity.nvd_base_score", Status.PASS, null);
    assertFinding(honest, "severity.nvd_severity", Status.PASS, null);
    assertFinding(honest, "exploitability.attack_vector", Status.UNVERIFIABLE, null);
    assertFinding(honest, "impact.availability", Status.UNVERIFIABLE, null);
    assertEquals(6, honest.unverifiable().stream()
        .filter(f -> f.path().startsWith("exploitability.") || f.path().startsWith("impact."))
        .count(), "AV, PR, UI, C, I, A: all six vector checks are unverifiable, not skipped");

    GroundingReport invented = GroundingValidator.validate(sparse, grounded());
    assertFinding(invented, "severity.nvd_base_score", Status.FAIL, Severity.HARD);
    assertFinding(invented, "severity.nvd_severity", Status.FAIL, Severity.HARD);
  }

  @Test
  void aKevListingDemandsActivelyExploited() {
    CveInput kev = input(V31, true, "Analyzed");

    GroundingReport r = GroundingValidator.validate(kev, grounded());
    assertFinding(r, "exploitability.exploit_maturity", Status.FAIL, Severity.HARD);

    GroundingReport ok = GroundingValidator.validate(kev, with(d -> {
      at(d, "exploitability").put("exploit_maturity", "ACTIVELY_EXPLOITED");
      at(d, "exploitability").put("likelihood", "HIGH");
    }));
    assertFinding(ok, "exploitability.exploit_maturity", Status.PASS, null);
  }

  @Test
  void exploitMaturityWithoutEvidenceIsOnlyASoftFlag() {
    CveInput untagged = new CveInput(
        INPUT.cveId(), INPUT.publishedDate(), INPUT.vulnStatus(), false, null, List.of(),
        "Plain description that makes no claims about attacks seen.", INPUT.cweIds(), V31,
        INPUT.cpeCategories(), INPUT.affected(),
        List.of(new CveInput.Reference(PR_URL, List.of("Patch"))));

    GroundingReport r = GroundingValidator.validate(untagged, grounded());
    assertFinding(r, "exploitability.exploit_maturity", Status.FAIL, Severity.SOFT);

    GroundingReport r2 = GroundingValidator.validate(untagged, with(d ->
        at(d, "exploitability").put("exploit_maturity", "UNPROVEN")));
    assertFinding(r2, "exploitability.exploit_maturity", Status.PASS, null);
  }

  @Test
  void cpeDerivedNamesAreSoftBecauseNvdCpeDataIsNoisy() {
    GroundingReport r = GroundingValidator.validate(INPUT, with(d -> {
      at(d, "affected").put("vendor", "Microsoft");
      at(d, "affected").putNull("product");
      at(d, "affected").put("component_type", "OPERATING_SYSTEM");
    }));

    assertFinding(r, "affected.vendor", Status.FAIL, Severity.SOFT);
    assertFinding(r, "affected.product", Status.FAIL, Severity.SOFT);
    assertFinding(r, "affected.component_type", Status.FAIL, Severity.SOFT);
    assertTrue(r.grounded(), "soft flags never make a result ungrounded");
  }

  @Test
  void withoutCpeTheAffectedNamesAreUnverifiable() {
    CveInput noCpe = new CveInput(
        INPUT.cveId(), INPUT.publishedDate(), INPUT.vulnStatus(), false, null, List.of(),
        INPUT.description(), INPUT.cweIds(), V31, List.of(), List.of(), INPUT.references());

    GroundingReport r = GroundingValidator.validate(noCpe, grounded());

    assertFinding(r, "affected.vendor", Status.UNVERIFIABLE, null);
    assertFinding(r, "affected.component_type", Status.UNVERIFIABLE, null);
  }

  @Test
  void mechanismFollowsTheCweMapWhenOneAppliesAndIsJudgementOtherwise() {
    GroundingReport r = GroundingValidator.validate(INPUT, with(d ->
        at(d, "weakness").put("mechanism", "INJECTION")));
    assertFinding(r, "weakness.mechanism", Status.FAIL, Severity.HARD);

    CveInput unmapped = new CveInput(
        INPUT.cveId(), INPUT.publishedDate(), INPUT.vulnStatus(), false, null, List.of(),
        INPUT.description(), List.of("CWE-31"), V31, INPUT.cpeCategories(), INPUT.affected(),
        INPUT.references());
    GroundingReport judgement = GroundingValidator.validate(unmapped, with(d -> {
      at(d, "weakness").put("mechanism", "INJECTION");
      at(d, "weakness").putArray("cwe_ids").add("CWE-31");
    }));
    assertFinding(judgement, "weakness.mechanism", Status.UNVERIFIABLE, null);
  }

  @Test
  void vulnerableVersionsMayBeProseButVersionTokensMustComeFromTheInput() {
    GroundingReport prose = GroundingValidator.validate(INPUT, with(d ->
        at(d, "affected").put("vulnerable_versions", "all released versions")));
    assertFinding(prose, "affected.vulnerable_versions", Status.UNVERIFIABLE, null);

    GroundingReport invented = GroundingValidator.validate(INPUT, with(d ->
        at(d, "affected").put("vulnerable_versions", ">= 0.0.300 and < 0.1.12")));
    assertFinding(invented, "affected.vulnerable_versions", Status.FAIL, Severity.SOFT);
  }

  @Test
  void versionTokensAreNotOnlyDottedNumbers() {
    CveInput firmware = new CveInput(
        "CVE-2026-86509", "2026-01-01", "Analyzed", false, null, List.of(),
        "A flaw has been found in D-Link DIR-895L A1_102b07. Debian ships 1:2.3-4; fixed in"
            + " commit 9fceb02d and build 12.3X48-D105. Versions 3.x are affected.",
        List.of(), null, List.of(), List.of(), List.of());

    GroundingReport r = GroundingValidator.validate(firmware, with(d -> {
      at(d, "affected").put("vulnerable_versions", "A1_102b07; Debian 1:2.3-4; v3.x");
      at(d, "affected").put("fixed_version", "12.3X48-D105 (commit 9fceb02d)");
      at(d, "severity").putNull("nvd_base_score");
      at(d, "severity").put("nvd_severity", "UNKNOWN");
      at(d, "severity").put("adjusted_severity", "UNKNOWN");
      at(d, "remediation").put("action", "PATCH");
      d.put("verdict", "WARN");
      d.put("priority", "P2");
    }));

    assertFinding(r, "affected.vulnerable_versions", Status.PASS, null);
    assertFinding(r, "affected.fixed_version", Status.PASS, null);

    GroundingReport wrongBuild = GroundingValidator.validate(firmware, with(d -> {
      at(d, "affected").put("fixed_version", "A1_102b08");
      at(d, "remediation").put("action", "PATCH");
    }));
    assertFinding(wrongBuild, "affected.fixed_version", Status.FAIL, Severity.HARD);
  }

  @Test
  void aDataGapThatDeniesSomethingTheInputContainsIsFlagged() {
    GroundingReport r = GroundingValidator.validate(INPUT, with(d ->
        d.putArray("data_gaps").add("no CVSS metrics").add("no fixed version published")));
    assertFinding(r, "data_gaps", Status.FAIL, Severity.SOFT);

    GroundingReport cwe = GroundingValidator.validate(INPUT, with(d ->
        d.putArray("data_gaps").add("No CWE ids assigned by NVD.")));
    assertFinding(cwe, "data_gaps", Status.FAIL, Severity.SOFT);

    // Gaps that mention CVSS or CPE without denying their presence are legitimate.
    GroundingReport aboutSomethingElse = GroundingValidator.validate(INPUT, with(d ->
        d.putArray("data_gaps")
            .add("no affected version boundaries (CPE wildcard only)")
            .add("no CVSS attack-vector justification for ADJACENT on a web endpoint")
            .add("affected CPE entries do not match the product named in the description")));
    assertFinding(aboutSomethingElse, "data_gaps", Status.PASS, null);

    GroundingReport qualified = GroundingValidator.validate(input(V2, false, "Analyzed"),
        with(d -> {
          at(d, "severity").put("nvd_base_score", 6.8);
          at(d, "severity").put("nvd_severity", "MEDIUM");
          at(d, "severity").put("adjusted_severity", "MEDIUM");
          d.putArray("data_gaps").add("no CVSS v3 metrics");
        }));
    assertFinding(qualified, "data_gaps", Status.PASS, null);
  }

  // --- invariants -----------------------------------------------------------------------------

  @Test
  void n1TheActionAndTheFixedVersionTellTheSameStory() {
    GroundingReport noFixButVersion = GroundingValidator.validate(INPUT, with(d ->
        at(d, "remediation").put("action", "NO_FIX_AVAILABLE")));
    assertFinding(noFixButVersion, "invariant.N1a", Status.FAIL, Severity.HARD);

    GroundingReport versionButMonitor = GroundingValidator.validate(INPUT, with(d ->
        at(d, "remediation").put("action", "MONITOR")));
    assertFinding(versionButMonitor, "invariant.N1b", Status.FAIL, Severity.HARD);

    GroundingReport patchWithoutVersion = GroundingValidator.validate(INPUT, with(d -> {
      at(d, "remediation").put("action", "PATCH");
      at(d, "affected").putNull("fixed_version");
    }));
    assertFinding(patchWithoutVersion, "invariant.N1a", Status.PASS, null);
    assertFinding(patchWithoutVersion, "invariant.N1b", Status.PASS, null);
  }

  @Test
  void n2ASeverityAdjustmentNeedsANonTrivialReason() {
    GroundingReport r = GroundingValidator.validate(INPUT, with(d -> {
      at(d, "severity").put("adjusted_severity", "CRITICAL");
      at(d, "severity").put("adjustment_reason", "Raised.");
    }));
    assertFinding(r, "invariant.N2", Status.FAIL, Severity.HARD);
  }

  @Test
  void n3UnknownSeverityAndNullScoreComeTogether() {
    GroundingReport r = GroundingValidator.validate(INPUT, with(d ->
        at(d, "severity").put("nvd_severity", "UNKNOWN")));
    assertFinding(r, "invariant.N3", Status.FAIL, Severity.HARD);
  }

  @Test
  void n4AndN5EncodeTheSystemPromptsBlockRule() {
    CveInput sparse = input(null, false, "Analyzed");
    GroundingReport r = GroundingValidator.validate(sparse, with(d -> {
      at(d, "severity").putNull("nvd_base_score");
      at(d, "severity").put("nvd_severity", "UNKNOWN");
      at(d, "exploitability").put("attack_vector", "LOCAL");
      at(d, "affected").putNull("fixed_version");
      at(d, "remediation").put("action", "MONITOR");
    }));

    assertFinding(r, "invariant.N4", Status.FAIL, Severity.HARD);
    assertFinding(r, "invariant.N5", Status.FAIL, Severity.HARD);
  }

  @Test
  void n6ARejectedRecordMustBeAllowedWithNoSeverity() {
    CveInput rejected = input(V31, false, "Rejected");
    GroundingReport r = GroundingValidator.validate(rejected, grounded());
    assertFinding(r, "invariant.N6", Status.FAIL, Severity.HARD);
  }

  @Test
  void n7AskingForAHumanMeansLowConfidence() {
    GroundingReport r = GroundingValidator.validate(INPUT, with(d -> {
      d.put("verdict", "NEEDS_HUMAN_REVIEW");
      d.put("confidence", "HIGH");
    }));
    assertFinding(r, "invariant.N7", Status.FAIL, Severity.HARD);
  }

  @Test
  void n8ToN10AreSoftConsistencyFlags() {
    GroundingReport r = GroundingValidator.validate(INPUT, with(d -> {
      at(d, "severity").put("adjusted_severity", "LOW");
      at(d, "severity").put("adjustment_reason", "Reachability is limited to one rare call.");
      d.put("priority", "P0");
      d.put("verdict", "ALLOW");
      at(d, "exploitability").put("exploit_maturity", "ACTIVELY_EXPLOITED");
      at(d, "exploitability").put("likelihood", "LOW");
    }));

    assertFinding(r, "invariant.N8", Status.FAIL, Severity.SOFT);
    assertFinding(r, "invariant.N9", Status.FAIL, Severity.SOFT);
    assertFinding(r, "invariant.N10", Status.PASS, null);
  }
}
