package com.n4d3sh1k4.security_service.dto.event;

public record PasswordResetEvent(
    String email,
    String token
) {}
