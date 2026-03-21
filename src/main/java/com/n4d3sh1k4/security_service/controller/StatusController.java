package com.n4d3sh1k4.security_service.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/status")
public class StatusController {

    @SecurityRequirement(name = "bearerAuth")
    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }

    @Operation(summary = "Получить данные текущего пользователя",
           description = "Возвращает ID и роли, извлеченные из заголовков Gateway")
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(Authentication authentication) {
        Map<String, Object> userDetails = Map.of(
            "userId", authentication.getName(),
            "roles", authentication.getAuthorities().stream()
                                    .map(GrantedAuthority::getAuthority)
                                    .toList(),
            "source", "Gateway Headers" // Для наглядности, что данные пришли не из БД
        );

        return ResponseEntity.ok(userDetails);
    }
}
