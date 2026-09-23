package com.n4d3sh1k4.security_service.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Schema(description = "Ответ с JWT токеном доступа")
@Data
@AllArgsConstructor
public class JwtResponse {
    @Schema(description = "Тип токена", example = "Bearer")
    private final String type = "Bearer";

    @Schema(description = "JWT access token", example = "eyJhbGciOiJIUzI1NiIs...")
    private String accessToken;
}