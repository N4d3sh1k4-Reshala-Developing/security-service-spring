package com.n4d3sh1k4.security_service.dto.event;

import java.time.Instant;

public record AccountLockedMessage(String email, Instant timestamp) {
}
