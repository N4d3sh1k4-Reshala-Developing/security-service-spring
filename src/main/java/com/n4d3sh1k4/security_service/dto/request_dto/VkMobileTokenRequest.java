package com.n4d3sh1k4.security_service.dto.request_dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Schema(description = "Запрос авторизации через VK ID (мобильный флоу)")
@Data
public class VkMobileTokenRequest {
    @Schema(description = "Код авторизации из VK ID SDK (callback onAuthCode)", example = "1234567890")
    @NotBlank
    private String code;

    @Schema(description = "PKCE codeVerifier, сгенерированный на устройстве", example = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    @NotBlank
    @Size(max = 128)
    private String codeVerifier;

    @Schema(description = "Уникальный идентификатор мобильного устройства от VK ID SDK", example = "abc123-def456")
    @Size(max = 64)
    private String deviceId;

    @Schema(description = "Произвольная строка состояния приложения (генерируется на устройстве)", example = "xyz789")
    @Size(max = 64)
    private String state;
}