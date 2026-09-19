package io.holbein.ai.secgateway.validation;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import io.holbein.ai.secgateway.schema.JsonSchema;
import tools.jackson.databind.JsonNode;

public final class SchemaValidator {
  private static final int MAX_VIOLATIONS = 20;

  private SchemaValidator() {
  }

  public static List<Violation> validate(JsonSchema schema, JsonNode root) {
    List<Violation> violations = new ArrayList<>();
    walk(schema, root, "", violations);
    return List.copyOf(violations);
  }

  private static void walk(JsonSchema schema, JsonNode node, String path, List<Violation> out) {
    if (out.size() >= MAX_VIOLATIONS) {
      return;
    }
    if (schema.anyOf() != null) {
      walkNullable(schema, node, path, out);
      return;
    }
    if (schema.enumValues() != null) {
      if (!node.isString() || !schema.enumValues().contains(node.asString())) {
        out.add(
            new Violation(
                path,
                "was " + render(node) + ", allowed: " + String.join(" | ", schema.enumValues())));
      }
      return;
    }
    switch (schema.type()) {
      case "object" -> walkObject(schema, node, path, out);
      case "array" -> walkArray(schema, node, path, out);
      case "string" -> requireType(node.isString(), "a string", node, path, out);
      case "number" -> requireType(node.isNumber(), "a number", node, path, out);
      case "boolean" -> requireType(node.isBoolean(), "a boolean", node, path, out);
      case "null" -> requireType(node.isNull(), "null", node, path, out);
      default -> throw new IllegalStateException("unsupported schema type: " + schema.type());
    }
  }

  private static void walkNullable(
      JsonSchema schema, JsonNode node, String path, List<Violation> out) {
    if (!node.isNull()) {
      walk(schema.anyOf().get(0), node, path, out);
    }
  }

  private static void walkObject(JsonSchema schema, JsonNode node, String path, List<Violation> out) {
    if (!node.isObject()) {
      requireType(false, "an object", node, path, out);
      return;
    }
    Map<String, JsonSchema> properties = schema.properties();

    if (Boolean.FALSE.equals(schema.additionalProperties())) {
      node.propertyNames()
          .forEach(
              name -> {
                if (!properties.containsKey(name) && out.size() < MAX_VIOLATIONS) {
                  out.add(
                      new Violation(
                          child(path, name), "unexpected field (the schema forbids extras)"));
                }
              });
    }
    for (Map.Entry<String, JsonSchema> property : properties.entrySet()) {
      String name = property.getKey();
      if (!node.has(name)) {
        out.add(new Violation(child(path, name), "required field is missing"));
      } else {
        walk(property.getValue(), node.get(name), child(path, name), out);
      }
    }
  }

  private static void walkArray(JsonSchema schema, JsonNode node, String path, List<Violation> out) {
    if (!node.isArray()) {
      requireType(false, "an array", node, path, out);
      return;
    }
    int index = 0;
    for (JsonNode element : node) {
      walk(schema.items(), element, path + "[" + index++ + "]", out);
      if (out.size() >= MAX_VIOLATIONS) {
        return;
      }
    }
  }

  private static void requireType(
      boolean ok, String expected, JsonNode node, String path, List<Violation> out) {
    if (!ok) {
      out.add(new Violation(path, "was " + render(node) + ", expected " + expected));
    }
  }

  private static String child(String path, String name) {
    return path.isEmpty() ? name : path + "." + name;
  }

  private static String render(JsonNode node) {
    String text = node.isString() ? "\"" + node.asString() + "\"" : node.toString();
    return text.length() <= 60 ? text : text.substring(0, 60) + "...";
  }
}
