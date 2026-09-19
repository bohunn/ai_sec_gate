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

  public void freeze(NvdaService nvd) {
    Path dir = root.resolve("corpus");
    Map<String, Object> manifest = new LinkedHashMap<>();
    Map<String, Object> records = new LinkedHashMap<>();
    List<Entry> entries = definition();

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
          System.out.printf("  [%2d/%d] %s%n", i + 1, entries.size(), entry.cveId());
          HttpRetry.pause(PACING_MS);
        }

        CveInput input = NvdaService.parse(entry.cveId(), body);
        records.put(
            entry.cveId(),
            Map.of(
                "stratum", entry.stratum(),
                "vuln_status", String.valueOf(input.vulnStatus()),
                "has_cvss", input.cvss() != null,
                "cwe_count", input.cweIds().size(),
                "cpe_categories", input.cpeCategories()));
      }
      manifest.put("frozen_at", Instant.now().toString());
      manifest.put("count", entries.size());
      manifest.put("records", records);
      Json.writePretty(dir.resolve("manifest.json"), manifest);
    } catch (IOException e) {
      throw new UncheckedIOException("Cannot write corpus to " + dir, e);
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
