package io.holbein.ai.secgateway.corpus;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import io.holbein.ai.secgateway.Csv;
import io.holbein.ai.secgateway.Json;
import io.holbein.ai.secgateway.model.CveInput;
import io.holbein.ai.secgateway.service.HttpRetry;
import io.holbein.ai.secgateway.service.NvdaService;

public final class CveCorpus {
  public record Entry(String cveId, String stratum) {}

  private final Path root;
  private List<Entry> definition;

  public CveCorpus(Path root) {
    this.root = root;
  }

  public List<Entry> definition() {
    if (definition != null) {
      return definition;
    }
    Path csv = root.resolve("corpus.csv");
    List<Entry> entries = new ArrayList<>();
    try {
      List<String> lines = Files.readAllLines(csv);
      for (String line : lines.subList(1, lines.size())) {
        List<String> cells = Csv.parseLine(line);
        if (cells.size() >= 2) {
          entries.add(
              new Entry(cells.get(0), cells.get(1)));
        }
      }
    } catch (IOException e) {
      throw new UncheckedIOException("Cannot read " + csv, e);
    }
    return definition = List.copyOf(entries);
  }

  private static final long PACING_MS = 7_000;

  /**
   * Fetches every record in corpus.csv that is not on disk yet and rewrites the manifest. Records
   * already on disk are never re-fetched, so extending the corpus leaves old records byte-identical:
   * {@code frozen_at} keeps the date of the first freeze, {@code last_extended_at} records the
   * extension, and each record carries the SHA-256 of its file so comparability on old records can
   * be checked mechanically (DECISIONS.md, "Comparability key").
   */
  public void freeze(NvdaService nvd) {
    Path dir = root.resolve("corpus");
    Map<String, Object> manifest = new LinkedHashMap<>();
    Map<String, Object> records = new LinkedHashMap<>();
    List<Entry> entries = definition();
    String previousFrozenAt = previousFrozenAt(dir.resolve("manifest.json"));
    boolean fetched = false;

    try {
      Files.createDirectories(dir);
      for (int i = 0; i < entries.size(); i++) {
        Entry entry = entries.get(i);
        Path file = dir.resolve(entry.cveId() + ".json");
        String body;

        if (Files.isRegularFile(file)) {
          body = Files.readString(file);
          System.out.printf("  [%2d/%d] %s (already frozen)%n", i + 1, entries.size(),
              entry.cveId());
        } else {
          body = nvd.fetchRaw(entry.cveId());
          Files.writeString(file, body);
          fetched = true;
          System.out.printf("  [%2d/%d] %s%n", i + 1, entries.size(), entry.cveId());
          HttpRetry.pause(PACING_MS);
        }

        CveInput input = NvdaService.parse(entry.cveId(), body);
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("stratum", entry.stratum());
        record.put("vuln_status", String.valueOf(input.vulnStatus()));
        record.put("has_cvss", input.cvss() != null);
        record.put("cwe_count", input.cweIds().size());
        record.put("cpe_categories", input.cpeCategories());
        record.put("sha256", sha256(body));
        records.put(entry.cveId(), record);
      }
      String now = Instant.now().toString();
      manifest.put("frozen_at", previousFrozenAt == null ? now : previousFrozenAt);
      if (fetched && previousFrozenAt != null) {
        manifest.put("last_extended_at", now);
      }
      manifest.put("count", entries.size());
      manifest.put("records", records);
      Json.writePretty(dir.resolve("manifest.json"), manifest);
    } catch (IOException e) {
      throw new UncheckedIOException("Cannot write corpus to " + dir, e);
    }
  }

  private static String previousFrozenAt(Path manifest) {
    if (!Files.isRegularFile(manifest)) {
      return null;
    }
    try {
      return Json.API.readTree(Files.readString(manifest)).path("frozen_at").asString(null);
    } catch (IOException e) {
      return null;
    }
  }

  private static String sha256(String body) {
    try {
      byte[] digest =
          java.security.MessageDigest.getInstance("SHA-256")
              .digest(body.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      return java.util.HexFormat.of().formatHex(digest);
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  public CveInput get(String cveId, NvdaService nvd) {
    Path file = root.resolve("corpus").resolve(cveId + ".json");
    return Files.isRegularFile(file) ? load(cveId) : nvd.fetchCve(cveId);
  }

  public String stratumOf(String cveId) {
    return definition().stream()
        .filter(e -> e.cveId().equals(cveId))
        .map(Entry::stratum)
        .findFirst()
        .orElse("");
  }

  public CveInput load(String cveId) {
    Path file = root.resolve("corpus").resolve(cveId + ".json");
    try {
      return NvdaService.parse(cveId, Files.readString(file));
    } catch (IOException e) {
      throw new UncheckedIOException("Not frozen yet - run 'freeze' first: " + file, e);
    }
  }

  public boolean isFrozen() {
    return Files.isRegularFile(root.resolve("corpus").resolve("manifest.json"));
  }
}
