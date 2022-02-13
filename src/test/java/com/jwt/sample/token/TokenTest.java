package com.jwt.sample.token;

import static com.jwt.sample.TestConstants.ALIAS;
import static com.jwt.sample.TestConstants.CERT_PATH;
import static com.jwt.sample.TestConstants.JWT_HEADER_JOSE;
import static com.jwt.sample.TestConstants.JWT_PAYLOAD_JOSE;
import static com.jwt.sample.TestConstants.PASSWORD;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.jose4j.lang.JoseException;
import org.junit.Test;

import com.jwt.sample.context.KeyStoreContext;
import com.jwt.sample.exceptions.SignatureContextException;
import com.jwt.sample.exceptions.SignatureGenerationException;
import com.jwt.sample.exceptions.SignatureVerificationException;

public class TokenTest {

    @Test
    public void generateJWTTest() throws SignatureContextException, SignatureGenerationException {
        KeyStoreContext keyStoreWrap = new KeyStoreContext(CERT_PATH, PASSWORD, ALIAS);

        String jwt = prepareJWT();

        RSAJWTToken token = new RSAJWTToken();
        byte[] jwtSignBytes = token.signPayload(keyStoreWrap, jwt.getBytes(StandardCharsets.UTF_8));
        String jwtSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(jwtSignBytes);

        assertNotNull(jwtSignature);
    }

    @Test
    public void compareSignMethodsTest() throws SignatureContextException, SignatureGenerationException, JoseException {
        String header = "{\"alg\":\"RS256\"}";
        String payload = "{\"jti\":\"155082791761700001\"}";

        Base64.Encoder base64 = Base64.getUrlEncoder();
        String payloadBase64 = base64.encodeToString(payload.getBytes(StandardCharsets.UTF_8));

        String notSingedJWT = base64.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "." + payloadBase64;

        Map<String, Object> headers = new HashMap<>();
        headers.put("alg", "RS256");

        KeyStoreContext keyStoreWrap = new KeyStoreContext(CERT_PATH, PASSWORD, ALIAS);

        RSAJWTToken token = new RSAJWTToken();
        byte[] jwtSimpleBytes = token.signPayload(keyStoreWrap, notSingedJWT.getBytes(StandardCharsets.UTF_8));
        String jwtSimpleStr = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(jwtSimpleBytes);
        String jwtSimple = notSingedJWT + "." + jwtSimpleStr;

        assertNotNull(jwtSimpleStr);
        assertNotNull(jwtSimple);
    }

    @Test
    public void validateJWTTest() throws SignatureContextException, SignatureGenerationException, SignatureVerificationException {
        KeyStoreContext keyStoreWrap = new KeyStoreContext(CERT_PATH, PASSWORD, ALIAS);

        String notSingedJWT = prepareJWT();

        RSAJWTToken token = new RSAJWTToken();
        byte[] jwtSimpleBytes = token.signPayload(keyStoreWrap, notSingedJWT.getBytes(StandardCharsets.UTF_8));

        boolean validToken = token.validateSignature(keyStoreWrap, jwtSimpleBytes, notSingedJWT.getBytes(StandardCharsets.UTF_8));

        assertTrue(validToken);
    }

    private String prepareJWT() {
        String josePayload = JWT_PAYLOAD_JOSE.replace("%iat", new Long(System.currentTimeMillis()).toString());
        josePayload = josePayload.replace("%exp", new Long(System.currentTimeMillis() + 15 * 60 * 100).toString());
        String josePayloadBase64 = Base64.getUrlEncoder().encodeToString(josePayload.getBytes(StandardCharsets.UTF_8));
        String joseHeaderBase64 = Base64.getUrlEncoder().encodeToString(JWT_HEADER_JOSE.getBytes(StandardCharsets.UTF_8));
        String jwt = joseHeaderBase64 + "." + josePayloadBase64;
        return jwt;
    }
}