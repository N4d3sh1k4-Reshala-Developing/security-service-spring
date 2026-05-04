package com.n4d3sh1k4.security_service.dto.request_dto;

import com.n4d3sh1k4.security_service.dto.validation.PasswordMatch;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Schema(description = "Сущность регистрации")
@Data
@PasswordMatch
public class RegisterRequest {
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Size(max = 50)
    private String email;

    public void setEmail(String email) {
        this.email = (email != null) ? email.toLowerCase().trim() : null;
    }

    @Schema(example = "Password#4848")
    @NotBlank(message = "Password is required")
    @Size(min = 8, max = 50, message = "Password must be between 8 and 50 characters")
    @Pattern(
        regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&*()])[a-zA-Z\\d!@#$%^&*()]+$",
        message = "The password must contain Latin characters, numbers, uppercase and lowercase letters."
    )
    private String password;

    @Schema(example = "Password#4848")
    private String confirmPassword;
}