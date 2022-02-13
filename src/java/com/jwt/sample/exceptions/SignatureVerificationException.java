package com.jwt.sample.exceptions;

public class SignatureVerificationException extends Exception {
    private static final long serialVersionUID = 3L;

    public SignatureVerificationException(Throwable cause) {
        super("Signature verification failure.", cause);
    }
}
