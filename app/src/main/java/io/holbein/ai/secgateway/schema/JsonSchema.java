package io.holbein.ai.secgateway.schema;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({
    "type",
    "description",
    "enum",
    "anyOf",
    "items",
    "properties",
    "required",
    "additionalProperties"
})
public record JsonSchema(
    @JsonProperty("type") String type,
    @JsonProperty("description") String description,
    @JsonProperty("enum") List<String> enumValues,
    @JsonProperty("anyOf") List<JsonSchema> anyOf,
    @JsonProperty("items") JsonSchema items,
    @JsonProperty("properties") Map<String, JsonSchema> properties,
    @JsonProperty("required") List<String> required,
    @JsonProperty("additionalProperties") Boolean additionalProperties) {
  private static final JsonSchema NULL = scalar("null", null);

  static JsonSchema string(String description) {
    return scalar("string", description);
  }

  static JsonSchema number(String description) {
    return scalar("number", description);
  }

  static JsonSchema bool(String description) {
    return scalar("boolean", description);
  }

  static <E extends Enum<E>> JsonSchema enumOf(Class<E> type, String description) {
    List<String> values = Arrays.stream(type.getEnumConstants()).map(Enum::name).toList();
    return new JsonSchema("string", description, values, null, null, null, null, null);
  }

  static JsonSchema arrayOf(JsonSchema items, String description) {
    return new JsonSchema("array", description, null, null, items, null, null, null);
  }

  static JsonSchema nullable(JsonSchema inner, String description) {
    JsonSchema bare = new JsonSchema(inner.type(), null, inner.enumValues(), null, inner.items(),
        inner.properties(), inner.required(), inner.additionalProperties());
    return new JsonSchema(null, description, null, List.of(bare, NULL), null, null, null, null);
  }

  public static Builder object() {
    return new Builder();
  }

  private static JsonSchema scalar(String type, String description) {
    return new JsonSchema(type, description, null, null, null, null, null, null);
  }

  public static final class Builder {
    private final Map<String, JsonSchema> properties = new LinkedHashMap<>();

    public Builder property(String name, JsonSchema schema) {
      properties.put(name, schema);
      return this;
    }

    public Builder string(String name, String description) {
      return property(name, JsonSchema.string(description));
    }

    public Builder nullableString(String name, String description) {
      return property(name, nullable(JsonSchema.string(null), description));
    }

    public Builder nullableNumber(String name, String description) {
      return property(name, nullable(JsonSchema.number(null), description));
    }

    public Builder nullableBool(String name, String description) {
      return property(name, nullable(JsonSchema.bool(null), description));
    }

    public <E extends Enum<E>> Builder enums(String name, Class<E> type, String description) {
      return property(name, enumOf(type, description));
    }

    public Builder stringArray(String name, String description) {
      return property(name, arrayOf(JsonSchema.string(null), description));
    }

    public JsonSchema build() {
      return new JsonSchema(
          "object",
          null,
          null,
          null,
          null,
          Collections.unmodifiableMap(new LinkedHashMap<>(properties)),
          List.copyOf(properties.keySet()),
          false);
    }
  }
}
