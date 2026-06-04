package com.n4d3sh1k4.security_service.exception;

import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import lombok.Getter;

@Getter
public class OAuthEmailAlreadyExistsException extends RuntimeException {
    private final String email;
    private final AuthProvider provider;
    private final String providerUserId;

    public OAuthEmailAlreadyExistsException(String email, AuthProvider provider, String providerUserId) {
        super("Account with this email already exists. Link required.");
        this.email = email;
        this.provider = provider;
        this.providerUserId = providerUserId;
    }
}
