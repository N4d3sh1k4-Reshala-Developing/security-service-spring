package com.n4d3sh1k4.security_service.dto.event;

public record NotificationEmailMessage(
    String email,
    String username,
    String token
) {}
