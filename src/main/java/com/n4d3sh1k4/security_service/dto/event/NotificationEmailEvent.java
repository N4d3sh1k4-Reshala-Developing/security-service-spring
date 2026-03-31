package com.n4d3sh1k4.security_service.dto.event;

public record NotificationEmailEvent(
        String email,
        String username,
        String token
) {
}