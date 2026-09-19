package io.holbein.ai.secgateway;

import java.util.ArrayList;
import java.util.List;

public final class Csv {
  private Csv() {}

  public static List<String> parseLine(String line) {
    List<String> cells = new ArrayList<>();
    StringBuilder cell = new StringBuilder();
    boolean quoted = false;

    for (int i = 0; i < line.length(); i++) {
      char c = line.charAt(i);
      if (c == '"') {
        if (quoted && i + 1 < line.length() && line.charAt(i + 1) == '"') {
          cell.append('"');
          i++;
        } else {
          quoted = !quoted;
        }
      } else if (c == ',' && !quoted) {
        cells.add(cell.toString());
        cell.setLength(0);
      } else {
        cell.append(c);
      }
    }
    cells.add(cell.toString());
    return cells;
  }

  public static String escape(String value) {
    if (value == null) {
      return "";
    }
    String cell = value.replace("\"", "\"\"").replace("\n", " ");
    return cell.contains(",") || cell.contains("\"") ? "\"" + cell + "\"" : cell;
  }
}
