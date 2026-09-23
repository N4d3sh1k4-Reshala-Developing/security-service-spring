package com.n4d3sh1k4.security_service.dto.request_dto;

import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Schema(description = "Сущность для линка стороннего провайдера авторизации")
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

    @Schema(description = "ID пользователя у провайдера", example = "123456789")
    @NotBlank
    private String providerUserId;
}
