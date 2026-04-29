package com.n4d3sh1k4.security_service.controller;

import com.n4d3sh1k4.security_service.dto.request_dto.UserRequest;
import com.n4d3sh1k4.security_service.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/user")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping
    public UserRequest getUser(Authentication authentication) {
        return userService.getUser(authentication.getName());
    }

    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Тестовый контроллер - возвращает роль пользователя в системе.")
    @GetMapping("/check-me")
    public String checkMe(Authentication authentication) {
        return "Your authorities: " + authentication.getAuthorities();
    }
}
