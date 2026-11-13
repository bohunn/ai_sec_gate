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

  /**
   * First 16 hex digits of the SHA-256 of {@code value} serialized with {@link #API}. Used for the
   * comparability-key elements in the run manifest; tests pin each to a constant so an unintended
   * change of shape, or a non-deterministic serialization, fails the build.
   */
  public static String sha256(Object value) {
    try {
      byte[] digest =
          java.security.MessageDigest.getInstance("SHA-256")
              .digest(API.writeValueAsString(value).getBytes(java.nio.charset.StandardCharsets.UTF_8));
      return java.util.HexFormat.of().formatHex(digest).substring(0, 16);
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private Json() {}
}
