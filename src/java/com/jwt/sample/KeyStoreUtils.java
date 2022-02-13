package com.jwt.sample;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jwt.sample.exceptions.SignatureContextException;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class KeyStoreUtils {

    private static final Logger logger = LoggerFactory.getLogger(KeyStoreUtils.class);

    private static final String KEYSTORE_DEFAULT_TYPE = "JKS";
    private static final String PEM_CERTIFICATE_PREFIX = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_CERTIFICATE_POSTFIX = "-----END CERTIFICATE-----";

    public static synchronized KeyStore loadKeyStore(String path, String password) throws SignatureContextException {
        return loadKeyStore(path, password, KEYSTORE_DEFAULT_TYPE);
    }

    private static synchronized KeyStore loadKeyStore(String path, String password, String keystoreType) throws SignatureContextException {
        InputStream keystoreStream = null;
        KeyStore keystore;
        try {
            File file = new File(path);
            if (file.exists()) {
                logger.debug("Load keystore by absolute path.");
                keystoreStream = FileUtils.openInputStream(file);

                keystore = KeyStore.getInstance(keystoreType);

                char[] storePassword = password.toCharArray();
                keystore.load(keystoreStream, storePassword);
            } else {
                logger.debug("Load keystore by relative path.");
                keystore = KeyStore.getInstance(keystoreType);
                keystoreStream = KeyStoreUtils.class.getResourceAsStream(path);
                if (keystoreStream == null) {
                    throw new SignatureContextException("Key Storage can't be found by path: " + path);
                }
                keystore.load(keystoreStream, password.toCharArray());
            }

        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
            throw new SignatureContextException("Exception occurred while Key Storage loading by path: " + path + System.lineSeparator() + e.getMessage());
        } finally {
            try {
                if (keystoreStream != null) {
                    keystoreStream.close();
                }
            } catch (IOException e) {
                throw new SignatureContextException("Exception occurred while stream closing for Key Storage " + path + System.lineSeparator() + e.getMessage());
            }
        }
        return keystore;
    }

    public static String extractPemCertificate(Certificate certificate) throws SignatureContextException {
        return extractPemCertificateInternal(certificate);
    }

    private static String extractPemCertificateInternal(Certificate certificate) throws SignatureContextException {
        if (certificate == null) {
            throw new SignatureContextException("Certificate is null and can not be wrapped to PEM certificate");
        }
        String certificateBase64;
        try {
            certificateBase64 = Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new SignatureContextException(e.getMessage());
        }
        String wrappedCert =
                PEM_CERTIFICATE_PREFIX + System.lineSeparator() + certificateBase64 + System.lineSeparator() + PEM_CERTIFICATE_POSTFIX;
        return wrappedCert;
    }


    public static Certificate extractCertificate(String alias, KeyStore keyStore) throws SignatureContextException {
        return extractCertificateInternal(alias, keyStore);
    }

    private static Certificate extractCertificateInternal(String alias, KeyStore keyStore) throws SignatureContextException {
        if (alias == null || alias.isEmpty()) {
            throw new SignatureContextException("Alias for certificate is not specified.");
        }
        if (keyStore == null) {
            throw new SignatureContextException("Keystore is not loaded. Certification and key data can not be extracted.");
        }
        try {
            return keyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new SignatureContextException("Exception occurred while data was extracted from Key Storage " + System.lineSeparator() + e.getMessage());
        }
    }

    public static Key extractKey(String alias, String keyPassword, KeyStore keyStore) throws SignatureContextException {
        return extractKeyInternal(alias, keyPassword, keyStore);
    }

    private static Key extractKeyInternal(String alias, String keyPassword, KeyStore keyStore) throws SignatureContextException {
        if (alias == null || alias.isEmpty()) {
            throw new SignatureContextException("Alias for certificate is not specified.");
        }
        if (keyStore == null) {
            throw new SignatureContextException("Keystore is not loaded. Certification and key data can not be extracted.");
        }
        try {
            char[] keyPasswordChar = keyPassword.toCharArray();
            return keyStore.getKey(alias, keyPasswordChar);

        } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
            throw new SignatureContextException("Exception occurred while data was extracted from Key Storage " + System.lineSeparator() + e.getMessage());
        }
    }

    public static X509Certificate extractCertificateX509(Certificate publicCertificate) throws SignatureContextException {
        return extractCertificateX509Internal(publicCertificate);
    }

    private static X509Certificate extractCertificateX509Internal(Certificate publicCertificate) throws SignatureContextException {
        if (publicCertificate instanceof X509Certificate) {
            return (X509Certificate) publicCertificate;
        } else {
            throw new SignatureContextException("Storage doesn't contain X509 certificate.");
        }
    }

}
