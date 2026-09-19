package io.holbein.ai.secgateway.service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;

import io.holbein.ai.secgateway.Json;
import io.holbein.ai.secgateway.model.CveInput;
import io.holbein.ai.secgateway.nvd.NvdCveResponse;

public class NvdaService {
  private static final String NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=";
  private final HttpClient client;

  public NvdaService() {
    client = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .build();
  }

  public CveInput fetchCve(String cveId) {
    return parse(cveId, fetchRaw(cveId));
  }

  public String fetchRaw(String cveId) {
    HttpResponse<String> response = HttpRetry.send(() -> fetch(cveId));
    if (response.statusCode() != 200) {
      throw new IllegalStateException(
          "NVD returned " + response.statusCode() + " for " + cveId + ": " + response.body());
    }
    return response.body();
  }

  public static CveInput parse(String cveId, String body) {
    NvdCveResponse parsed = Json.NVD.readValue(body, NvdCveResponse.class);
    if (parsed.vulnerabilities() == null || parsed.vulnerabilities().isEmpty()) {
      throw new IllegalStateException("NVD has no record for " + cveId);
    }
    return CveInput.from(parsed.vulnerabilities().get(0).cve());
  }

  private HttpResponse<String> fetch(String cveId) {
    HttpRequest request = HttpRequest.newBuilder(URI.create(NVD_CVE_API + cveId))
        .method("GET", BodyPublishers.noBody())
        .timeout(Duration.ofSeconds(30))
        .build();

    try {
      return client.send(request, BodyHandlers.ofString());
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
