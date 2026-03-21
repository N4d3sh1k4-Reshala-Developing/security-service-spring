package com.n4d3sh1k4.security_service.dto.request_dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Schema(description = "Сущность для восстановления пароля по почте")
@Data
public class ForgotPasswordRequest {

    @NotBlank
    @Email
    @Size(max = 50)
    private String email;
}