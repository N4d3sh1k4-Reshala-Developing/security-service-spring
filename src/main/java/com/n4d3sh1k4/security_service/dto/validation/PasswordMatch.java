package com.n4d3sh1k4.security_service.dto.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = GenericPasswordMatchValidator.class) // Указываем новый валидатор
public @interface PasswordMatch {
    String message() default "Passwords do not match";

    String passwordField() default "password";        // Имя основного поля
    String confirmPasswordField() default "confirmPassword"; // Имя поля подтверждения

    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}
