package com.n4d3sh1k4.security_service.dto.validation;

import com.n4d3sh1k4.security_service.dto.request_dto.RegisterRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PasswordMatchValidator implements ConstraintValidator<PasswordMatch, RegisterRequest> {
    @Override
    public boolean isValid(RegisterRequest dto, ConstraintValidatorContext context) {
        if (dto.getPassword() == null || dto.getConfirmPassword() == null) {
            return false;
        }
        return dto.getPassword().equals(dto.getConfirmPassword());
    }
}
