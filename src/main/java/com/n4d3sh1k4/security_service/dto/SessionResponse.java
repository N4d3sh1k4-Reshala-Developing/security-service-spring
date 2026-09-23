package com.n4d3sh1k4.security_service.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;
import java.util.UUID;

@Schema(description = "Информация об активной сессии")
public record SessionResponse(
    @Schema(description = "ID сессии (refresh token)")
    UUID id,

    @Schema(description = "IP-адрес")
    String ip,

    @Schema(description = "Город, определённый по IP (null, если не удалось)")
    String city,

    @Schema(description = "User-Agent браузера")
    String userAgent,

    @Schema(description = "Дата создания сессии")
    Instant createdAt,

    @Schema(description = "Дата истечения сессии")
    Instant expiresAt,

    @Schema(description = "Запомнить меня")
    boolean rememberMe,

    @Schema(description = "Текущая сессия")
    boolean current
) {}
