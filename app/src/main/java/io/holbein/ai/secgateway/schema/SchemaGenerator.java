package io.holbein.ai.secgateway.schema;

import java.lang.reflect.RecordComponent;
import java.util.List;

import tools.jackson.databind.PropertyNamingStrategies;

public final class SchemaGenerator {

  private static final Names NAMES = new Names();

  private SchemaGenerator() {
  }

  public static JsonSchema of(Class<?> record) {
    if (!record.isRecord()) {
      throw new IllegalArgumentException(record + " is not a record");
    }
    JsonSchema.Builder object = JsonSchema.object();
    for (RecordComponent component : record.getRecordComponents()) {
      object.property(NAMES.of(component.getName()), schemaFor(component));
    }
    return object.build();
  }

  private static JsonSchema schemaFor(RecordComponent component) {
    Field field = component.getAnnotation(Field.class);
    String description = field == null ? null : field.value();
    JsonSchema schema = baseFor(component, description);
    return field != null && field.nullable() ? JsonSchema.nullable(schema, description) : schema;
  }

  private static JsonSchema baseFor(RecordComponent component, String description) {
    Class<?> type = component.getType();

    if (type.isRecord()) {
      return of(type);
    }
    if (type.isEnum()) {
      return JsonSchema.enumOf(type.asSubclass(Enum.class), description);
    }
    if (type == String.class) {
      return JsonSchema.string(description);
    }
    if (type == Double.class || type == double.class) {
      return JsonSchema.number(description);
    }
    if (type == Boolean.class || type == boolean.class) {
      return JsonSchema.bool(description);
    }
    if (type == List.class) {
      return JsonSchema.arrayOf(JsonSchema.string(null), description);
    }
    throw new IllegalArgumentException(
        "No schema mapping for " + component.getName() + " of type " + type);
  }

  private static final class Names extends PropertyNamingStrategies.SnakeCaseStrategy {

    String of(String name) {
      return translate(name);
    }
  }
}
