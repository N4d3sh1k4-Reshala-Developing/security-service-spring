package com.n4d3sh1k4.security_service.dto.exception_dto;

import lombok.Getter;

@Getter
public enum ErrorCode {
    USER_ALREADY_EXISTS("A user with this email already exists"),
    INVALID_CREDENTIALS("Incorrect login or password"),
    TOKEN_EXPIRED("Token has expired"),
    TOKEN_NOT_FOUND("Token not found"),
    VALIDATION_ERROR("Field validation error"),
    USER_NOT_FOUND("The user was not found in the system"),
    INTERNAL_ERROR("Internal server error"),
    TOO_MANY_REQUESTS("Too many requests");

    private final String defaultMessage;

    ErrorCode(String defaultMessage) {
        this.defaultMessage = defaultMessage;
    }

}