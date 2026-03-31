package com.n4d3sh1k4.security_service.dto.validation;

import com.n4d3sh1k4.security_service.dto.request_dto.RegisterRequest;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class PasswordMatchValidator implements ConstraintValidator<PasswordMatch, RegisterRequest> {

    @Override
    public void initialize(PasswordMatch passwordMatch) {
    }

    @Override
    public boolean isValid(RegisterRequest dto, ConstraintValidatorContext context) {
        // Проверка на null, чтобы не поймать NullPointerException
        if (dto.getPassword() == null || dto.getConfirmPassword() == null) {
            return false;
        }

        boolean isValid = dto.getPassword().equals(dto.getConfirmPassword());

        if (!isValid) {
            // 1. Отключаем стандартное сообщение (которое вешается на весь класс)
            context.disableDefaultConstraintViolation();

            // 2. Вешаем новое сообщение на конкретное поле "confirmPassword"
            context.buildConstraintViolationWithTemplate(context.getDefaultConstraintMessageTemplate())
                   .addPropertyNode("confirmPassword")
                   .addConstraintViolation();
        }

        return isValid;
    }
}