package com.jwt.sample.utils;

import org.junit.Test;

import com.jwt.sample.KeyStoreUtils;
import com.jwt.sample.exceptions.SignatureContextException;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;

import static com.jwt.sample.TestConstants.*;
import static org.junit.Assert.assertNotNull;

public class KeyStoreUtilsTest {

    @Test
    public void loadKeyStoreByRelativeTest() throws SignatureContextException, KeyStoreException {
        KeyStore keyStore = KeyStoreUtils.loadKeyStore(CERT_PATH, PASSWORD);

        assertNotNull(keyStore);
        assertNotNull(keyStore.getCertificate(ALIAS));
    }

    @Test
    public void loadKeyStoreByAbsPathTest() throws SignatureContextException, KeyStoreException {
        String currentDir = System.getProperty("user.dir");
        KeyStore keyStore = KeyStoreUtils.loadKeyStore(currentDir + "/" + CERT_PATH, PASSWORD);

        assertNotNull(keyStore);
        assertNotNull(keyStore.getCertificate(ALIAS));
    }

    @Test
    public void loadKeyStoreFromResourcesTest() throws SignatureContextException, KeyStoreException {
        KeyStore keyStore = KeyStoreUtils.loadKeyStore(CERT_PATH, PASSWORD);

        assertNotNull(keyStore);
        assertNotNull(keyStore.getCertificate(ALIAS));
    }

    @Test
    public void extractCertificateTest() throws SignatureContextException {
        KeyStore keyStore = KeyStoreUtils.loadKeyStore(CERT_PATH, PASSWORD);
        Certificate certificate = KeyStoreUtils.extractCertificate(ALIAS, keyStore);

        assertNotNull(certificate);
    }
}