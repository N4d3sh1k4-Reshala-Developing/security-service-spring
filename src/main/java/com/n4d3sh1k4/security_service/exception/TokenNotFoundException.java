package com.n4d3sh1k4.security_service.exception;

public class TokenNotFoundException extends RuntimeException {
    public TokenNotFoundException(String message) {
        super(message);
    }

    public TokenNotFoundException() {
        super();
    }
}
