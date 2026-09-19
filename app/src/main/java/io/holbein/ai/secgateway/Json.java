package io.holbein.ai.secgateway;

import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.json.JsonMapper;

public final class Json {
  public static final ObjectMapper API = JsonMapper.builder()
      .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
      .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
      .build();

  public static final ObjectMapper NVD = JsonMapper.builder().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
      .build();

  private static final tools.jackson.databind.ObjectWriter PRETTY =
      API.writerWithDefaultPrettyPrinter();

  public static void writePretty(java.nio.file.Path path, Object value)
      throws java.io.IOException {
    java.nio.file.Files.writeString(path, PRETTY.writeValueAsString(value));
  }

  private Json() {}
}
