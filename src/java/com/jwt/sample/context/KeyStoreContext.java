package com.jwt.sample.context;

import com.jwt.sample.KeyStoreUtils;
import com.jwt.sample.exceptions.SignatureContextException;

import lombok.Data;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Objects;

@Data
public class KeyStoreContext extends Context {
    private static final Logger logger = LoggerFactory.getLogger(KeyStoreContext.class);

    @Getter
    @Setter
    private String path;
    @Getter
    @Setter
    private String storagePassword;
    @Getter
    @Setter
    private String keyAlias;
    @Getter
    @Setter
    private String keyPassword;

    @Getter
    private PublicKey publicKey;
    @Getter
    private PrivateKey privateKey;
    @Getter
    private Certificate publicCertificate;
    @Getter
    private X509Certificate publicCertificateX509;
    @Getter
    private KeyStore keyStore;

    /**
     * Initialize certificate storage context with required details for signing and/or verification
     *
     * @param storagePath     - certificate path
     * @param storagePassword - key storage and certificate password in case they are the same
     * @param keyAlias        - certificate key alias
     * @throws SignatureContextException - if provided keystore data is incorrect
     */
    public KeyStoreContext(@NonNull String storagePath, @NonNull String storagePassword, @NonNull String keyAlias) throws SignatureContextException {
        this.path = storagePath;
        this.storagePassword = storagePassword;
        this.keyPassword = storagePassword;
        this.keyAlias = keyAlias;

        initializeCertificateData();
    }

    /**
     * Initialize certificate storage context with required details for signification and/or verification
     *
     * @param storagePath     - certificate path
     * @param storagePassword - key storage and certificate password in case they are the same
     * @param keyPassword     - key certificate password
     * @param keyAlias        - certificate key alias
     * @throws SignatureContextException - if provided keystore data is incorrect
     */
    public KeyStoreContext(@NonNull String storagePath, @NonNull String storagePassword, @NonNull String keyPassword, @NonNull String keyAlias) throws SignatureContextException {
        this.path = storagePath;
        this.storagePassword = storagePassword;
        this.keyPassword = keyPassword;
        this.keyAlias = keyAlias;

        initializeCertificateData();
    }

    private void initializeCertificateData() throws SignatureContextException {
        logger.trace("Start load key store by path: {}", this.path);
        keyStore = KeyStoreUtils.loadKeyStore(this.path, this.storagePassword);
        logger.trace("Key store is loaded.");

        this.privateKey = (PrivateKey) KeyStoreUtils.extractKey(this.keyAlias, this.keyPassword, keyStore);
        logger.trace("Private key is extracted by alias: {}", this.keyAlias);
        this.publicCertificate = KeyStoreUtils.extractCertificate(this.keyAlias, keyStore);
        logger.trace("Public certificate is extracted by alias: {}", this.keyAlias);
        this.publicCertificateX509 = KeyStoreUtils.extractCertificateX509(this.publicCertificate);
        logger.trace("X509 public certificate is extracted by alias: {}", this.keyAlias);
        this.publicKey = publicCertificate.getPublicKey();
        logger.trace("Public key is extracted from certificate");
    }

	@Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        //if (!super.equals(o)) return false;
        KeyStoreContext context = (KeyStoreContext) o;
        return Objects.equals(publicCertificate, context.publicCertificate) &&
                Objects.equals(privateKey, context.getPrivateKey());
    }

    @Override
    public int hashCode() {
        return Objects.hash(publicCertificate, privateKey);
    }
}
