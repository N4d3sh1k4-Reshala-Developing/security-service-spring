package com.n4d3sh1k4.security_service.dto.request_dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Schema(description = "Сущность для авторизации")
@Data
public class LoginRequest {
    @NotBlank
    @Email
    @Size(max = 50)
    private String email;

    @Schema(example = "Password#4848")
    @NotBlank
    @Size(max = 50)
    private String password;

    @Schema(example = "true")
    boolean rememberMe;
}
