package com.n4d3sh1k4.security_service.dto.request_dto;

import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class LinkSocialRequest {
    @NotBlank
    @Email
    private String email;

    @NotBlank
    private String password;

    @NotNull
    private AuthProvider provider;

    @NotBlank
    private String providerUserId;
}
