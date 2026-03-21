package com.n4d3sh1k4.security_service.controller;

import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/users")
public class UserController {

    @Hidden
    @GetMapping()
    public ResponseEntity<?> UserInfo() {
        return ResponseEntity.ok().build();
    }

    @Hidden
    @PatchMapping()
    public ResponseEntity<?> UserUpdate() {
        return ResponseEntity.ok().build();
    }

    @Hidden
    @PostMapping()
    public ResponseEntity<?> UserDeactivate() {
        return ResponseEntity.ok().build();
    }

    @Hidden
    @PostMapping("/password")
    public ResponseEntity<?> ResetPassword() {
        return ResponseEntity.ok().build();
    }

    @Hidden
    @PostMapping("/sessions")
    public ResponseEntity<?> Sessions() {
        return ResponseEntity.ok().build();
    }

    @Hidden
    @PostMapping("/verify-email")
    public ResponseEntity<?> VerifyEmail() {
        return ResponseEntity.ok().build();
    }

    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Тестовый контроллер - возвращает роль пользователя в системе.")
    @GetMapping("/check-me")
    public String checkMe(Authentication authentication) {
        return "Your authorities: " + authentication.getAuthorities();
    }
}
