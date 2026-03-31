package com.n4d3sh1k4.security_service.controller;

import com.n4d3sh1k4.security_service.domain.repository.RoleRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import com.n4d3sh1k4.security_service.dto.*;
import com.n4d3sh1k4.security_service.dto.request_dto.ForgotPasswordRequest;
import com.n4d3sh1k4.security_service.dto.request_dto.LoginRequest;
import com.n4d3sh1k4.security_service.dto.request_dto.RegisterRequest;
import com.n4d3sh1k4.security_service.dto.request_dto.ResetPasswordRequest;
import com.n4d3sh1k4.security_service.jwt.JwtProvider;
import com.n4d3sh1k4.security_service.security.UserDetailsServiceImpl;
import com.n4d3sh1k4.security_service.service.AuthService;
import com.n4d3sh1k4.security_service.service.RefreshTokenService;
import com.n4d3sh1k4.security_service.utils.CookieUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.Map;

@Tag(name="Авторизация", description = "всё про авторизацию")
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final AuthService authService;

    public AuthController(AuthenticationManager authenticationManager, RefreshTokenService refreshTokenService, UserRepository userRepository, UserDetailsServiceImpl userDetailsService, JwtProvider jwtProvider, UserDetailsServiceImpl userDetailsServiceImpl, PasswordEncoder passwordEncoder, RoleRepository roleRepository, CookieUtils cookieUtils, AuthService authService) {
        this.authenticationManager = authenticationManager;
        this.authService = authService;
    }

    //Есть
    @Operation(summary = "Регистрация пользователей", description = "Позволяет добавить пользователя в систему. После регистрации возвращает клиенту пару ключей авторизации: acces в body и refresh в куки.")
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest req) {
        authService.registerUser(req);
        return ResponseEntity.ok("Registration successful. Please check your email.");
    }

    //Есть
    @GetMapping("/confirm")
    public ResponseEntity<?> confirmRegistration(@RequestParam("token") String token) {
        try {
            authService.activateUser(token);
            return ResponseEntity.ok("Аккаунт успешно активирован! Теперь вы можете войти.");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/resend-confirmation")
    public ResponseEntity<?> resendToken(@RequestParam("email") String email) {
        try {
            authService.resendConfirmToken(email);
            return ResponseEntity.ok("Новое письмо с подтверждением отправлено на вашу почту.");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    //Есть
    @Operation(summary = "Авторизация пользователей", description = "Позволяет авторизоваться пользователю в системе. После авторизации возвращает клиенту пару ключей авторизации: acces в body и refresh в куки.")
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        AuthServiceResult result = authService.loginUser(loginRequest);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, result.getCookie())
                .body(new JwtResponse(result.getAccesToken()));
    }

    //Есть
    @Operation(summary = "Обновление refresh токена авторизации", description = "Позволяет фронту обновить refresh токен пользователя без необходимости повторного входа а аккаунт по истечению времени пребывания авторизованным.")
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@CookieValue(name = "refreshToken", required = false) String refreshToken) {
        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        AuthServiceResult result = authService.refreshToken(refreshToken);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, result.getCookie())
                .body(new JwtResponse(result.getAccesToken()));
    }

    //Есть
    @Operation(summary = "Выход пользователя из аккаунта", description = "Позволяет пользователю обнулить текущую сессию. Удаляет токен из куки.")
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@CookieValue(name = "refreshToken", required = false) String refreshToken, Principal principal) {
        String userId = principal.getName();
        AuthServiceResult result = authService.logoutUser(userId, refreshToken);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, result.getCookie())
                .body("Logged out successfully");
    }

    //Под вопросом
    @Operation(summary = "Восстановление пароля", description = "Принимает почту пользователя и отправляет на неё письмо для восстановления пароля.")
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.createPasswordResetToken(request.getEmail());
        return ResponseEntity.ok(HttpStatus.OK);
    }

    //Под вопросом
    @Operation(summary = "Смена пароля", description = "Позволяет сменить пароль при наличии токена из письма с почты.")
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request.getToken(), request.getNewPassword());
        return ResponseEntity.ok(HttpStatus.OK);
    }
}