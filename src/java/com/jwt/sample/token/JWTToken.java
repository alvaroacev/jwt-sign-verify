package com.jwt.sample.token;

import com.jwt.sample.context.Context;
import com.jwt.sample.exceptions.SignatureException;
import com.jwt.sample.exceptions.SignatureContextException;
import com.jwt.sample.exceptions.SignatureGenerationException;
import com.jwt.sample.exceptions.SignatureVerificationException;

import java.util.Map;

public interface JWTToken {
    /**
     * Signs array of bytes using SHA256RSA algorithm
     *
     * @param context - context contains private key to sign payload
     * @param payload - content which should be signed
     * @return signature
     * @throws SignatureGenerationException - if any exception happens during signature generation
     * @throws SignatureContextException    - if context is invalid
     */
    byte[] signPayload(Context context, byte[] payload) throws SignatureGenerationException, SignatureContextException;

    /**
     * Signs array of bytes base on provided algorithm
     *
     * @param context   - context contains private key to sign payload
     * @param payload   - content which should be signed
     * @param algorithm - algorithm name
     * @return signature
     * @throws SignatureGenerationException - if any exception happens during signature generation
     * @throws SignatureContextException    - if context is invalid
     */
    byte[] signPayload(Context context, byte[] payload, String algorithm) throws SignatureGenerationException, SignatureContextException;

    /**
     * Validates signature for data
     *
     * @param context   - context contains public certificate for signature verification
     * @param signature - calculated signature to be verified
     * @param data      - signed content to verify signature for
     * @return - true/false for valid/invalid signature
     * @throws SignatureVerificationException - if any exception happens during signature validation
     * @throws SignatureContextException      - if context is invalid
     */
    boolean validateSignature(Context context, byte[] signature, byte[] data) throws SignatureVerificationException, SignatureContextException;

    /**
     * Creates NR signature base on claims
     *
     * @param context   - context with required information for signature
     * @param claimsMap - map of NR claims
     * @return signed token
     * @throws SignatureContextException - if context is invalid
     * @throws SignatureException      - if NR creation or signature fails
     */
    String createSignature(Context context, Map<String, Object> claimsMap) throws SignatureContextException, SignatureException;
}
