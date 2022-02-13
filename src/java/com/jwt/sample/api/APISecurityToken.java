package com.jwt.sample.api;

import com.jwt.sample.context.KeyStoreContext;
import com.jwt.sample.exceptions.SignatureException;
import com.jwt.sample.exceptions.SignatureContextException;
import com.jwt.sample.exceptions.SignatureGenerationException;
import com.jwt.sample.exceptions.SignatureVerificationException;
import com.jwt.sample.token.RSAJWTToken;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Implementation for certificate (JKS)
 */
public class APISecurityToken extends APISecurity {

    private static final Logger logger = LoggerFactory.getLogger(APISecurityToken.class);

    /**
     * Initialize context base on certificate for generation/verification signature.
     *
     * @param context - key and certificate storage information
     */
    public APISecurityToken(KeyStoreContext context) {
        super(context);
    }

    /**
     * Signs data content using private certificate from key storage.
     * All certificate data is saved in context
     *
     * @param data - array of bytes to be signed
     * @return calculated signature for data
     * @throws SignatureGenerationException - if signature generation failed
     * @throws SignatureContextException - if provided keystore data is incorrect
     */
    @Override
    public byte[] sign(byte[] data) throws SignatureGenerationException, SignatureContextException {
        RSAJWTToken token = new RSAJWTToken();
        logger.trace("Start certificate signification.");
        byte[] signature = token.signPayload(context, data);
        return signature;
    }

    /**
     * Creates and signs content by certificate base on claims.
     * Audience and payload are mandatory claims.
     *
     * @param claimsMap - map of claims used to build signed content
     * @return signature
     * @throws SignatureException - if token can't be generated or signed
     */
    @Override
    public String sign(Map<String, Object> claimsMap) throws SignatureException {
        RSAJWTToken token = new RSAJWTToken();
        logger.trace("Start certificate signification.");
        String signature = token.createSignature(context, claimsMap);
        return signature;
    }

    /**
     * Validates signature calculated for data content
     *
     * @param signature - provided signature as array of bytes
     * @param data      - content was signed
     * @return true/false verification result
     * @throws SignatureVerificationException - if provided signature is invalid
     * @throws SignatureContextException - if provided context is invalid
     */
    @Override
    public boolean verify(byte[] signature, byte[] data) throws SignatureVerificationException, SignatureContextException {
        RSAJWTToken token = new RSAJWTToken();
        logger.trace("Start certificate validation.");
        return token.validateSignature(context, signature, data);
    }

}