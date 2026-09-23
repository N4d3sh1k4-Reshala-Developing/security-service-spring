package com.n4d3sh1k4.security_service.dto.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

import java.util.Set;

public class RussianEmailValidator implements ConstraintValidator<RussianEmail, String> {

    private static final Set<String> ALLOWED_DOMAINS = Set.of(
        "mail.ru", "yandex.ru", "ya.ru", "rambler.ru", "bk.ru",
        "list.ru", "inbox.ru", "bigmir.net",
        "tut.by", "mail.by", "yandex.by", "yandex.kz",
        "yandex.com", "narod.ru", "rumbler.ru", "pochta.ru",
        "e-dostavka.ru", "smtp.ru", "hotbox.ru", "mail15.com",
        "mail.ru.com", "yandex-team.ru", "ya.by"
    );

    @Override
    public boolean isValid(String value, ConstraintValidatorContext context) {
        if (value == null) {
            return true;
        }

        int atIndex = value.indexOf('@');
        if (atIndex < 0) {
            return false;
        }

        String domain = value.substring(atIndex + 1).toLowerCase().trim();

        return ALLOWED_DOMAINS.contains(domain);
    }
}