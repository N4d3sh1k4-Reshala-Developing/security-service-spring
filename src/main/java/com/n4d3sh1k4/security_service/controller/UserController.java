package com.n4d3sh1k4.security_service.controller;

import com.n4d3sh1k4.common.exception.BaseException;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import com.n4d3sh1k4.security_service.dto.UserData;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@Tag(name = "Пользователи", description = "Управление пользователями")
@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;

    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Данные текущего пользователя",
               description = "Возвращает username, email и связанные аккаунты (identities).")
    @GetMapping
    public UserData getCurrentUser(Authentication authentication) {
        User user = userRepository.findById(parseUserId(authentication.getName()))
                .orElseThrow(() -> new BaseException("User not found", "USER_NOT_FOUND", HttpStatus.NOT_FOUND));
        return toUserData(user);
    }

    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Проверить свои роли",
               description = "Возвращает список authorities текущего пользователя.")
    @GetMapping("/check-me")
    public String checkMe(Authentication authentication) {
        return "Your authorities: " + authentication.getAuthorities();
    }

    private UUID parseUserId(String name) {
        try {
            return UUID.fromString(name);
        } catch (IllegalArgumentException e) {
            throw new BaseException("User not found", "USER_NOT_FOUND", HttpStatus.NOT_FOUND);
        }
    }

    private UserData toUserData(User user) {
        return new UserData(
                user.getUsername() != null ? user.getUsername() : "",
                user.getEmail(),
                user.getIdentities().stream()
                        .map(identity -> new UserData.UserIdentityDto(
                                identity.getId() != null ? identity.getId().toString() : null,
                                identity.getProvider().name(),
                                identity.getProviderUserId(),
                                identity.getCreatedAt() != null ? identity.getCreatedAt().toString() : null))
                        .toList());
    }
}
