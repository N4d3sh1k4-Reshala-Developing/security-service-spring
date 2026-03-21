package com.n4d3sh1k4.security_service.exception;

public class TokenExpiredException extends RuntimeException{
    public TokenExpiredException(String message) {
        super(message);
    }

    public TokenExpiredException() {
        super();
    }
}
