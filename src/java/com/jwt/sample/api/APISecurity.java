package com.jwt.sample.api;

import com.jwt.sample.context.Context;
import com.jwt.sample.exceptions.SignatureException;
import com.jwt.sample.exceptions.SignatureContextException;
import com.jwt.sample.exceptions.SignatureGenerationException;
import com.jwt.sample.exceptions.SignatureVerificationException;

import java.util.Map;

public abstract class APISecurity {

    protected Context context;

    public APISecurity(Context context) {
        this.context = context;
    }

    /**
     * Signs data content
     *
     * @param data - array of bytes to be signed
     * @return signature as array of bytes
     * @throws SignatureGenerationException - if token can't be signed
     * @throws SignatureContextException - if context is invalid
     */
    public abstract byte[] sign(byte[] data) throws SignatureContextException, SignatureGenerationException;

    /**
     * Creates and signs content base on claims
     *
     * @param claimsMap - map of claims used to build signed content
     * @return signature
     * @throws SignatureContextException - if context is invalid
     * @throws SignatureException - if token can't be generated or signed
     */
    public abstract String sign(Map<String, Object> claimsMap) throws SignatureContextException, SignatureException;

    /**
     * Validates signature calculated for data content
     *
     * @param signature - provided signature as array of bytes
     * @param data      - content was signed
     * @return is valid or invalid signature
     * @throws SignatureVerificationException - if token is invalid
     * @throws SignatureContextException - if context is invalid
     */
    public abstract boolean verify(byte[] signature, byte[] data) throws SignatureVerificationException, SignatureContextException;

    /**
     * @return context - container of required details for signification and/or verification
     */
    public Context getContext() {
        return context;
    }
}
