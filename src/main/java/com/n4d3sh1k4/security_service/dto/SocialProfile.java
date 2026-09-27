package com.n4d3sh1k4.security_service.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Профиль пользователя, полученный и проверенный на стороне провайдера OAuth")
public record SocialProfile(
        @Schema(description = "ID пользователя у провайдера (берётся только из ответа провайдера)")
        String providerUserId,

        @Schema(description = "Email провайдера (может быть null, если провайдер его не отдаёт)")
        String email,

        @Schema(description = "Имя")
        String firstName,

        @Schema(description = "Фамилия")
        String lastName,

        @Schema(description = "Телефон в формате 79xxxxxxxxx")
        String phone
) {}
