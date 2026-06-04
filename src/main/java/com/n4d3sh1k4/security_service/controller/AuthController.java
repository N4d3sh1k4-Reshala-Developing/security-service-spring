package com.n4d3sh1k4.security_service.controller;

import com.n4d3sh1k4.common.exception.TokenNotFoundException;
import com.n4d3sh1k4.security_service.domain.repository.RoleRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import com.n4d3sh1k4.security_service.dto.*;
import com.n4d3sh1k4.security_service.dto.request_dto.*;
import com.n4d3sh1k4.security_service.jwt.JwtProvider;
import com.n4d3sh1k4.security_service.security.UserDetailsServiceImpl;
import com.n4d3sh1k4.security_service.service.AuthService;
import com.n4d3sh1k4.security_service.service.RefreshTokenService;
import com.n4d3sh1k4.security_service.service.YandexAuthService;
import com.n4d3sh1k4.security_service.utils.CookieUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@Tag(name = "Авторизация", description = "всё про авторизацию")
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final AuthService authService;
    private final YandexAuthService yandexAuthService;

    public AuthController(AuthenticationManager authenticationManager, RefreshTokenService refreshTokenService, UserRepository userRepository, UserDetailsServiceImpl userDetailsService, JwtProvider jwtProvider, UserDetailsServiceImpl userDetailsServiceImpl, PasswordEncoder passwordEncoder, RoleRepository roleRepository, CookieUtils cookieUtils, AuthService authService, YandexAuthService yandexAuthService) {
        this.authenticationManager = authenticationManager;
        this.authService = authService;
        this.yandexAuthService = yandexAuthService;
    }

    @Operation(summary = "Регистрация пользователей", description = "Позволяет добавить пользователя в систему. После регистрации возвращает клиенту пару ключей авторизации: acces в body и refresh в куки.")
    @PostMapping("/register")
    public ResponseEntity<Object> register(@Valid @RequestBody RegisterRequest req) {
        authService.registerUser(req);
        return ResponseEntity.ok().build();
    }

    @GetMapping("/confirm-email")
    public ResponseEntity<?> confirmRegistration(
            @RequestParam("token") String token,
            @RequestHeader("User-Agent") String userAgent
    ) {
        authService.activateUser(token);
        if (isMobile(userAgent)) {
            return ResponseEntity.ok().build();
        } else {
            String htmlBody = """
                        <!DOCTYPE html>
                        <html lang="ru">
                            <head>
                                <meta charset="UTF-8">
                                <title>Подтверждение почты</title>
                                <style>
                                    body { font-family: sans-serif; text-align: center; padding-top: 50px; }
                                    .button { background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
                                </style>
                            </head>
                            <body>
                                <h1>Подтверждение почты</h1>
                                <p>Ваша почта подтверждена. Войдите в аккаунт в приложении.</p>
                                <br><br>
                                <p style="margin-top: 30px; font-size: 0.8em;">Нет приложения? <a href="https://github.com/N4d3sh1k4-Reshala-Developing/reshala-android-app">Скачать из GitHub</a></p>
                            </body>
                        </html>
                    """;

            return ResponseEntity.ok()
                    .contentType(MediaType.valueOf("text/html;charset=UTF-8"))
                    .body(htmlBody);
        }
    }

    public boolean isMobile(String userAgent) {
        if (userAgent == null) return false;
        String ua = userAgent.toLowerCase();
        return ua.contains("mobi");
    }

    @PostMapping("/resend-confirmation")
    public ResponseEntity<?> resendToken(@RequestParam("email") String email) {
        authService.resendConfirmToken(email);
        return ResponseEntity.ok().build();

    }

    @Operation(summary = "Авторизация пользователей", description = "Позволяет авторизоваться пользователю в системе. После авторизации возвращает клиенту пару ключей авторизации: acces в body и refresh в куки.")
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        AuthServiceResult result = authService.loginUser(loginRequest);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, result.getCookie())
                .body(new JwtResponse(result.getAccessToken()));
    }

    @Operation(summary = "Обновление refresh токена авторизации", description = "Позволяет фронту обновить refresh токен пользователя без необходимости повторного входа а аккаунт по истечению времени пребывания авторизованным.")
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@CookieValue(name = "refreshToken", required = false) String refreshToken) {
        if (refreshToken == null) {
            throw new TokenNotFoundException("Refresh token not found", "UNAUTHORIZED", HttpStatus.UNAUTHORIZED);
        }
        AuthServiceResult result = authService.refreshToken(refreshToken);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, result.getCookie())
                .body(new JwtResponse(result.getAccessToken()));
    }

    @Operation(summary = "Выход пользователя из аккаунта", description = "Позволяет пользователю обнулить текущую сессию. Удаляет токен из куки.")
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@CookieValue(name = "refreshToken", required = false) String refreshToken, Principal principal) {
        String userId = principal.getName();
        AuthServiceResult result = authService.logoutUser(userId, refreshToken);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, result.getCookie())
                .body("Logged out successfully");
    }

    @Operation(summary = "Восстановление пароля", description = "Принимает почту пользователя и отправляет на неё письмо для восстановления пароля.")
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.createPasswordResetToken(request.getEmail());
        return ResponseEntity.ok().build();
    }

    @Operation(summary = "Смена пароля (API)", description = "Вызывается из приложения для финальной смены пароля.")
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request.getToken(), request.getPassword());
        return ResponseEntity.ok().build();
    }

    @Operation(summary = "Страница сброса (Браузер)", description = "То, что видит пользователь при клике из почты.")
    @GetMapping(value = "/reset-password", produces = "text/html; charset=UTF-8")
    public ResponseEntity<String> showResetPage(@RequestParam("token") String token) {
        String htmlBody = """
                    <!DOCTYPE html>
                    <html lang="ru">
                        <head>
                            <meta charset="UTF-8">
                            <title>Сброс пароля</title>
                            <style>
                                body { font-family: sans-serif; text-align: center; padding-top: 50px; }
                                .button { background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; }
                            </style>
                        </head>
                        <body>
                            <h1>Сброс пароля</h1>
                            <p>Для безопасности мы меняем пароль только внутри приложения.</p>
                            <br><br>
                            <a href="reshala://api/v0/auth/reset-password?token=%s" class="button">Открыть в приложении</a>
                            <p style="margin-top: 30px; font-size: 0.8em;">Нет приложения? <a href="https://github.com/N4d3sh1k4-Reshala-Developing/reshala-android-app">Скачать из GitHub</a></p>
                        </body>
                    </html>
                """.formatted(token);

        return ResponseEntity.ok()
                .contentType(MediaType.valueOf("text/html;charset=UTF-8"))
                .body(htmlBody);
    }


    @PostMapping("/yandex-mobile")
    public ResponseEntity<?> yandexMobile(@RequestBody YandexMobileTokenRequest request) {
        AuthServiceResult result = yandexAuthService.authenticateMobile(request.getAccessToken());

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, result.getCookie())
                .body(new JwtResponse(result.getAccessToken()));
    }

    @ExceptionHandler(com.n4d3sh1k4.security_service.exception.OAuthEmailAlreadyExistsException.class)
    public ResponseEntity<?> handleOAuthEmailAlreadyExists(com.n4d3sh1k4.security_service.exception.OAuthEmailAlreadyExistsException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(java.util.Map.of(
                        "error", "email_exists_link_required",
                        "email", ex.getEmail(),
                        "provider", ex.getProvider().name(),
                        "providerUserId", ex.getProviderUserId()
                ));
    }

    @Operation(summary = "Привязка соцсети", description = "Привязывает соцсеть к аккаунту после ввода пароля.")
    @PostMapping("/link-social")
    public ResponseEntity<?> linkSocial(@Valid @RequestBody LinkSocialRequest request) {
        AuthServiceResult result = authService.linkSocialAccount(request);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, result.getCookie())
                .body(new JwtResponse(result.getAccessToken()));
    }
}