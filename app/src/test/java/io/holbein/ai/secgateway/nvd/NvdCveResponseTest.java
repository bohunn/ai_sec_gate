package io.holbein.ai.secgateway.nvd;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.time.LocalDateTime;
import io.holbein.ai.secgateway.Json;
import org.junit.jupiter.api.Test;

class NvdCveResponseTest {
  @Test
  void deserializesNvdCveApiResponse() throws Exception {
    NvdCveResponse response;
    try (InputStream in = getClass().getResourceAsStream("/nvd-cve-sample.json")) {
      response = Json.NVD.readValue(in, NvdCveResponse.class);
    }

    assertEquals(1, response.totalResults());
    assertEquals("NVD_CVE", response.format());
    assertEquals(LocalDateTime.parse("2026-08-18T13:51:57.715"), response.timestamp());

    NvdCveResponse.Cve cve = response.vulnerabilities().get(0).cve();
    assertEquals("CVE-2019-1010218", cve.id());
    assertEquals("Modified", cve.vulnStatus());
    assertEquals(2, cve.descriptions().size());
    assertTrue(cve.descriptions().get(0).value().contains("Cherokee"));

    assertEquals(7.5, cve.metrics().cvssMetricV31().get(0).cvssData().baseScore());
    assertEquals("HIGH", cve.metrics().cvssMetricV31().get(0).cvssData().baseSeverity());
    assertEquals("MEDIUM", cve.metrics().cvssMetricV2().get(0).baseSeverity());
    assertEquals(false, cve.metrics().cvssMetricV2().get(0).acInsufInfo());

    assertEquals("CWE-787", cve.weaknesses().get(1).description().get(0).value());
    assertEquals(
        "1.2.103",
        cve.configurations().get(0).nodes().get(0).cpeMatch().get(0).versionEndIncluding());
    assertEquals(2, cve.references().size());
  }
}
