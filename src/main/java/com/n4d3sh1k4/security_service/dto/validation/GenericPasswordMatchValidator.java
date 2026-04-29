package com.n4d3sh1k4.security_service.dto.validation;

import org.springframework.beans.BeanWrapperImpl;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

public class GenericPasswordMatchValidator implements ConstraintValidator<PasswordMatch, Object> {

    private String passwordFieldName;
    private String confirmPasswordFieldName;

    @Override
    public void initialize(PasswordMatch constraintAnnotation) {
        this.passwordFieldName = constraintAnnotation.passwordField();
        this.confirmPasswordFieldName = constraintAnnotation.confirmPasswordField();
    }

    @Override
    public boolean isValid(Object value, ConstraintValidatorContext context) {
        Object passwordValue = new BeanWrapperImpl(value).getPropertyValue(passwordFieldName);
        Object confirmPasswordValue = new BeanWrapperImpl(value).getPropertyValue(confirmPasswordFieldName);

        boolean isValid = passwordValue != null && passwordValue.equals(confirmPasswordValue);

        if (!isValid) {
            context.disableDefaultConstraintViolation();
            context.buildConstraintViolationWithTemplate(context.getDefaultConstraintMessageTemplate())
                   .addPropertyNode(confirmPasswordFieldName)
                   .addConstraintViolation();
        }

        return isValid;
    }
}
