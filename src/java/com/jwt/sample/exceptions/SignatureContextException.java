package com.jwt.sample.exceptions;

public class SignatureContextException extends Exception {
	private static final long serialVersionUID = -5688630602500033158L;

	public SignatureContextException(String message) {
        super(message);
    }

}
