package com.jwt.sample.exceptions;

public class SignatureException extends Exception {
	private static final long serialVersionUID = 2611805131497659096L;

	public SignatureException(String message) {
        super(message);
    }

}
