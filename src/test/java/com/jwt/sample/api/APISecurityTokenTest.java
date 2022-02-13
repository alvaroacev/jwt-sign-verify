package com.jwt.sample.api;

import static com.jwt.sample.TestConstants.ALIAS;
import static com.jwt.sample.TestConstants.CERT_PATH;
import static com.jwt.sample.TestConstants.PASSWORD;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.Test;

import com.jwt.sample.context.KeyStoreContext;
import com.jwt.sample.exceptions.SignatureContextException;
import com.jwt.sample.exceptions.SignatureGenerationException;
import com.jwt.sample.exceptions.SignatureVerificationException;

public class APISecurityTokenTest {

    @Test
    public void calculateSignatureTest() throws SignatureContextException, SignatureGenerationException {
        KeyStoreContext context = new KeyStoreContext(CERT_PATH, PASSWORD, ALIAS);
        APISecurityToken apiSecurityToken = new APISecurityToken(context);

        byte[] signatureBytes = apiSecurityToken.sign("test".getBytes(StandardCharsets.UTF_8));
        String signatureBase64 = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
        assertNotNull(signatureBase64);
        assertTrue(signatureBase64.contains("p3KgBLwYTW3YqjCy64h5HxnmpVMAFFDoAs11XQakDrIfjDhbFmKS4uAzhZLtaXRa5akUMttDSWhFUM7TdTHY4HprYcCePry6oPuYkdSTKAn6hyD6MIJBYukh0DbWY9cvwAlBavoqTN3DYDaL01M7UZNSwbiyqUeoO-HNItUSgplOgISGjHxPRwuIDsVjt-EX9bXd0aUj9OnmpvLf_HR2xPVyp2vgKzPGxqLoJTMIY29aH2ugxc3pOjDhWEE12xpKghYFxQMqeENHr3Is-CWvMo-j9u15YfOeQl7guguXOnrQn-5OUEq2lXx1exVuLiVf37phywmG1GA_S0ce--ectw"));
    }

    @Test
    public void validateSignatureTest() throws SignatureContextException, SignatureGenerationException, SignatureVerificationException {
        KeyStoreContext keyStoreWrap = new KeyStoreContext(CERT_PATH, PASSWORD, ALIAS);
        APISecurityToken apiSecurityToken = new APISecurityToken(keyStoreWrap);
        String payload = "someTestTextGoingBeSigned";

        byte[] signature = apiSecurityToken.sign(payload.getBytes(StandardCharsets.UTF_8));

        boolean validToken = apiSecurityToken.verify(signature, payload.getBytes(StandardCharsets.UTF_8));

        assertTrue(validToken);
    }
}