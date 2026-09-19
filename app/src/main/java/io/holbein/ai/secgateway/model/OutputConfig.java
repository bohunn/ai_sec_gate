package io.holbein.ai.secgateway.model;

import io.holbein.ai.secgateway.schema.JsonSchema;

public record OutputConfig(Format format) {
  public record Format(String type, JsonSchema schema) {}

  public static OutputConfig jsonSchema(JsonSchema schema) {
    return new OutputConfig(new Format("json_schema", schema));
  }
}
