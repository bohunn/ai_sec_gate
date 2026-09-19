package io.holbein.ai.secgateway.schema;

import io.holbein.ai.secgateway.model.CveTriage;
import io.holbein.ai.secgateway.model.OutputConfig;

public final class CveTriageSchema {

  private static final JsonSchema SCHEMA = SchemaGenerator.of(CveTriage.class);
  private static final OutputConfig OUTPUT_CONFIG = OutputConfig.jsonSchema(SCHEMA);

  private CveTriageSchema() {}

  public static JsonSchema schema() {
    return SCHEMA;
  }

  public static OutputConfig outputConfig() {
    return OUTPUT_CONFIG;
  }
}
