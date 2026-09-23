package com.n4d3sh1k4.security_service.dto.validation;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ ElementType.FIELD, ElementType.PARAMETER })
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = RussianEmailValidator.class)
public @interface RussianEmail {
    String message() default "Only Russian email domains are allowed (@mail.ru, @yandex.ru, etc.). Foreign email providers are not accepted.";

    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}