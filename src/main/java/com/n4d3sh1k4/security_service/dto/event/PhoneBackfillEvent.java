package com.n4d3sh1k4.security_service.dto.event;

import java.util.UUID;

public record PhoneBackfillEvent(
        UUID userId,
        String phone) {}