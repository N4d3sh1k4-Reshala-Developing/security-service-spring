package com.n4d3sh1k4.security_service.dto.request_dto;

import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Schema(description = "Сущность для линка стороннего провайдера авторизации. " +
        "providerUserId клиент не передаёт: сервер получает его из проверенного ответа провайдера.")
@Data
public class LinkSocialRequest {
    @Schema(description = "Email пользователя", example = "user@example.com")
    @NotBlank
    @Email
    @Size(max = 50)
    private String email;

    @Schema(example = "Password#4848")
    @NotBlank
    @Size(max = 50)
    private String password;

    @Schema(description = "Провайдер авторизации")
    @NotNull
    private AuthProvider provider;

    @Schema(description = "Свежий код авторизации VK ID (обязателен для provider=VK)", example = "1234567890")
    @Size(max = 512)
    private String code;

    @Schema(description = "PKCE codeVerifier из VK ID SDK (если SDK его возвращает)", example = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    @Size(max = 128)
    private String codeVerifier;

    @Schema(description = "Уникальный идентификатор мобильного устройства от VK ID SDK", example = "abc123-def456")
    @Size(max = 255)
    private String deviceId;

    @Schema(description = "Произвольная строка состояния приложения (генерируется на устройстве)", example = "xyz789")
    @Size(max = 255)
    private String state;

    @Schema(description = "Свежий OAuth access token Яндекса (обязателен для provider=YANDEX)")
    @Size(max = 2048)
    private String accessToken;
}
