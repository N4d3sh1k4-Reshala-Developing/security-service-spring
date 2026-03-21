package com.n4d3sh1k4.security_service.dto.request_dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Schema(description = "Сущность восстановления пароля")
@Data
public class ResetPasswordRequest {

    @Schema(example = "fda96fb5-5e1f-44b4-a942-3b6c05f41b79")
    private String token;

    @Schema(example = "Password#4848")
    @NotBlank
    @Size(min = 8, max = 50)
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)[a-zA-Z\\d]+$",
             message = "Пароль должен содержать латиницу, цифры, заглавные и строчные буквы")
    private String newPassword;
}