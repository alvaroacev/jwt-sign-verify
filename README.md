# jwt-sign-verify
This sample project provides a simple API to sign and verify a JWT token

Class <code> com.jwt.sample.api.APISecurityToken </code> implements two simple APIs to sign and verify a signature using a certificate. The certificate is initialized based on a <code>com.jwt.sample.context.KeyStoreContext</code> , including both private and public key for signature verification

Take a look at the JUnit tests for details