package com.n4d3sh1k4.security_service.exception;

public class ServerErrorException extends RuntimeException {
    public ServerErrorException(String message) {
        super(message);
    }
}
