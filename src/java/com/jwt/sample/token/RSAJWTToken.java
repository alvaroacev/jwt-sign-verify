package com.jwt.sample.token;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;

import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.jwt.sample.context.Context;
import com.jwt.sample.context.KeyStoreContext;
import com.jwt.sample.exceptions.SignatureException;
import com.jwt.sample.exceptions.SignatureContextException;
import com.jwt.sample.exceptions.SignatureGenerationException;
import com.jwt.sample.exceptions.SignatureVerificationException;

public class RSAJWTToken implements JWTToken {

    private static Logger logger = LoggerFactory.getLogger(RSAJWTToken.class);

    /**
     * Creates a JWT in format: base64Headers.base64Payload.base64Signature
     * Headers are alg, x5c, typ;
     *
     * @param context   - key store context
     * @param claimsMap - map of NR claims
     * @return signed token in format: base64URLEncodeHeaders.base64URLEncodePayload.Base64URLEncodeSignature
     * @throws SignatureException - if JWS creation fails
     */
    @Override
    public String createSignature(Context context, Map<String, Object> claimsMap) throws SignatureException {
    	return createSignatureInternal(context, claimsMap);
    }
    
    private String createSignatureInternal(Context context, Map<String, Object> claimsMap) throws SignatureException {

        final float claimExpMin = 15;
        Base64.Encoder base64 = Base64.getUrlEncoder();
        logger.trace("Claim expiration time is set to {} min.", claimExpMin);
        if(context instanceof KeyStoreContext) {
        	KeyStoreContext keyStoreWrap = (KeyStoreContext) context;
        	
        	 if (isValidClaimsMap(claimsMap)) {
                 try {
                     Gson gson = new GsonBuilder().disableHtmlEscaping().create();
                     String toJson = gson.toJson(claimsMap.get("payload"));
                     String payloadDigest ;
                     try {
                         payloadDigest = getDigest(base64.encode(toJson.getBytes(StandardCharsets.UTF_8)));
                         logger.debug("Payload digest is calculated: {}", payloadDigest);
                     } catch (SignatureGenerationException e) {
                         logger.error("Payload digest calculation issue." + System.lineSeparator() + e.getMessage());
                         throw new SignatureException("Payload digest calculation issue." + System.lineSeparator() + e.getMessage());
                     }

                     JwtClaims jwtClaims = new JwtClaims();
                     jwtClaims.setIssuedAtToNow();
                     jwtClaims.setExpirationTimeMinutesInTheFuture(claimExpMin);
                     jwtClaims.setGeneratedJwtId();
                     jwtClaims.setSubject(keyStoreWrap.getPublicCertificateX509().getSubjectDN().getName());
                     jwtClaims.setAudience(claimsMap.get("audience").toString());
                     jwtClaims.setStringClaim("digest", payloadDigest);

                     if (null != claimsMap.get("issuer") && !claimsMap.get("issuer").toString().isEmpty()) {
                         jwtClaims.setIssuer(claimsMap.get("issuer").toString());
                     }

                     JsonWebSignature jws = new JsonWebSignature();
                     jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
                     jws.setHeader("type", "JWT");
                     jws.setPayload(jwtClaims.toJson());
                     jws.setCertificateChainHeaderValue(keyStoreWrap.getPublicCertificateX509());

                     jws.setKey(keyStoreWrap.getPrivateKey());

                     String jwt = jws.getCompactSerialization();
                     logger.debug("Built JWT: {}", jwt);
                     return jwt;
                 } catch (JoseException e) {
                     logger.error("Unexpected problem generating JWS.{}{}", System.lineSeparator(), e.getMessage());
                     throw new SignatureException("Unexpected problem generating JWS." + System.lineSeparator() + e.getMessage());
                 }
             } else {
                 logger.error("Claims map is missing a mandatory claim.");
                 throw new SignatureException("Claims map is missing a mandatory claim.");
             }
        } else { 
        	throw new SignatureException("context is not valid");
        }
    }

    /**
     * Signs array of bytes using SHA256RSA algorithm
     *
     * @param context - context contains private key to sign payload
     * @param payload - content which should be signed
     * @return signed token in format: base64URLEncodeHeaders.base64URLEncodePayload.Base64URLEncodeSignature
     * @throws SignatureGenerationException - if any exception happens during signature generation
     * @throws SignatureContextException - if context is invalid
     */
    @Override
    public byte[] signPayload(Context context, byte[] payload) throws SignatureGenerationException, SignatureContextException {
        return signPayload(context, payload, Constants.SIGNATURE_ALGORITHM);
    }

    /**
     * Signs array of bytes base on provided algorithm
     *
     * @param context       - context contains private key to sign payload
     * @param payload       - content which should be signed
     * @param signAlgorithm - sign algorithm name
     * @return signature
     * @throws SignatureGenerationException - if any exception happens during signature generation
     * @throws SignatureContextException - if context is invalid
     */
    @Override
    public byte[] signPayload(Context context, byte[] payload, String signAlgorithm) throws SignatureGenerationException, SignatureContextException {
        return signInternal(context, payload, signAlgorithm);
    }
    
    private byte[] signInternal(Context context, byte[] payload, String signAlgorithm) throws SignatureGenerationException, SignatureContextException {
        try {
            if (!(context instanceof KeyStoreContext)) {
                logger.error("Given context expected to be KeyStoreContext.class");
                throw new SignatureContextException("Given context expected to be KeyStoreContext.class");
            }
            logger.trace("Start signing token.");
            KeyStoreContext keyStoreContext = (KeyStoreContext) context;
            Signature signature = Signature.getInstance(signAlgorithm);
            signature.initSign(keyStoreContext.getPrivateKey());
            signature.update(payload);
            byte[] payloadSignature = signature.sign();
            logger.trace("Signature calculated: {}", payloadSignature);
            return payloadSignature;

        } catch (NoSuchAlgorithmException e) {
            logger.error("Signature instance can't be created by {} algorithm.", signAlgorithm);
            throw new SignatureGenerationException(new Throwable("Signature instance can't be created by " + signAlgorithm + "algorithm.\r\n" + e.getMessage()));
        } catch (InvalidKeyException e) {
            logger.error("Error to init signature instance with private key.");
            throw new SignatureGenerationException(new Throwable("Error to init signature instance with private key.\r\n" + e.getMessage()));
        } catch (java.security.SignatureException e) {
            logger.error("Error generating the signature.");
            throw new SignatureGenerationException(new Throwable("Error generating the signature.\r\n" + e.getMessage()));
        }
    }

    /**
     * Validates signature for data
     *
     * @param context   - context contains public certificate for signature verification
     * @param signature - calculated signature to be verified
     * @param data      - signed content to verify signature for
     * @return - true/false for valid/invalid signature
     * @throws SignatureVerificationException - if any exception happens during signature validation
     * @throws SignatureContextException - if context is invalid
     */
    @Override
    public boolean validateSignature(Context context, byte[] signature, byte[] data) throws SignatureVerificationException, SignatureContextException {
    	return validateSignatureInternal(context, signature, data);
    }
    
    private boolean validateSignatureInternal(Context context, byte[] signature, byte[] data) throws SignatureVerificationException, SignatureContextException {

        if (signature == null || signature.length == 0) {
            logger.error("Validation JWT is null or empty. Nothing to verify.");
            return false;
        }
        if (!(context instanceof KeyStoreContext)) {
            logger.error("Given context expected to be KeyStoreContext.class");
            throw new SignatureContextException("Given context expected to be KeyStoreContext.class");
        }

        KeyStoreContext keyStoreContext = (KeyStoreContext) context;
        try {
            Signature signatureInstance = Signature.getInstance(Constants.SIGNATURE_ALGORITHM);

            signatureInstance.initVerify(keyStoreContext.getPublicKey());
            signatureInstance.update(data);
            boolean isValid = signatureInstance.verify(signature);
            logger.debug("Signature validation finished with result: {}", isValid);
            return isValid;
        } catch (NoSuchAlgorithmException e) {
            logger.error("Signature instance can't be created by {} algorithm.\r\n{}", Constants.SIGNATURE_ALGORITHM, e.getMessage());
            throw new SignatureVerificationException(new Throwable("Signature instance can't be created by " + Constants.SIGNATURE_ALGORITHM + "algorithm.\r\n" + e.getMessage()));
        } catch (InvalidKeyException e) {
            logger.error("Error to init signature instance with public key.\r\n" + e.getMessage());
            throw new SignatureVerificationException(new Throwable("Error to init signature instance with public key.\r\n" + e.getMessage()));
        } catch (java.security.SignatureException e) {
            logger.error("Error verifying the signature.\r\n" + e.getMessage());
            throw new SignatureVerificationException(new Throwable("Error verifying the signature.\r\n" + e.getMessage()));
        }
    }

    private boolean isValidClaimsMap(Map<String, Object> claimsMap) {
        boolean audExists = claimsMap.containsKey("audience");
        logger.trace("Claims contains audience: {}", audExists);
        boolean payloadExists = claimsMap.containsKey("payload");
        logger.trace("Claims contains payload: {}", payloadExists);

        return audExists && payloadExists;
    }

    private String getDigest(byte[] payload) throws SignatureGenerationException {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(md.digest(payload));
        } catch (NoSuchAlgorithmException e) {
            logger.error("Exception while creating the digest : " + e.getMessage());
            throw new SignatureGenerationException(e.getCause());
        }
    }
}