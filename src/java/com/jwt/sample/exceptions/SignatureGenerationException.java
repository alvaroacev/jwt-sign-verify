package com.jwt.sample.exceptions;

public class SignatureGenerationException extends Exception {
    private static final long serialVersionUID = 2L;

    public SignatureGenerationException(Throwable cause) {
        super("Signature generation failure.", cause);
    }
}
