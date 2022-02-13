package com.jwt.sample;

public final class TestConstants {
    public static final String CERT_PATH = "src/test/resources/jwt-keystore.keystore";
    public static final String ALIAS = "jwt";
    public static final String PASSWORD = "jwtKeyStore123!";

    public static final String JWT_HEADER_JOSE = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    public static final String JWT_PAYLOAD_JOSE = "{\"jti\":\"cCI6IkpXVCJ9\",\"sub\":\"1234567890\",\"name\":\"JWT Commons\",\"admin\":true,\"iat\":1516239022}";
}
