package com.n4d3sh1k4.security_service.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@Tag(name = "Пользователи", description = "Управление пользователями")
@RestController
@RequestMapping("/users")
public class UserController {

    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Проверить свои роли",
               description = "Возвращает список authorities текущего пользователя.")
    @GetMapping("/check-me")
    public String checkMe(Authentication authentication) {
        return "Your authorities: " + authentication.getAuthorities();
    }
}