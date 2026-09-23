package com.n4d3sh1k4.security_service.controller;

import com.n4d3sh1k4.security_service.exception.OAuthEmailAlreadyExistsException;
import com.n4d3sh1k4.security_service.domain.repository.RoleRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import com.n4d3sh1k4.security_service.dto.*;
import com.n4d3sh1k4.security_service.dto.request_dto.*;
import com.n4d3sh1k4.security_service.jwt.JwtProvider;
import com.n4d3sh1k4.security_service.security.UserDetailsServiceImpl;
import com.n4d3sh1k4.security_service.service.AuthService;
import com.n4d3sh1k4.security_service.service.RefreshTokenService;
import com.n4d3sh1k4.security_service.service.VkAuthService;
import com.n4d3sh1k4.security_service.service.YandexAuthService;
import com.n4d3sh1k4.security_service.utils.ClientIpUtils;
import com.n4d3sh1k4.security_service.utils.CookieUtils;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Tag(name="Авторизация", description = "всё про авторизацию")
@RestController
@Slf4j
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final AuthService authService;
    private final YandexAuthService  yandexAuthService;
    private final VkAuthService vkAuthService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(AuthenticationManager authenticationManager, RefreshTokenService refreshTokenService, UserRepository userRepository, UserDetailsServiceImpl userDetailsService, JwtProvider jwtProvider, UserDetailsServiceImpl userDetailsServiceImpl, PasswordEncoder passwordEncoder, RoleRepository roleRepository, CookieUtils cookieUtils, AuthService authService, YandexAuthService yandexAuthService, VkAuthService vkAuthService) {
        this.authenticationManager = authenticationManager;
        this.authService = authService;
        this.yandexAuthService = yandexAuthService;
        this.vkAuthService = vkAuthService;
        this.refreshTokenService = refreshTokenService;
    }

    @Operation(summary = "Регистрация пользователей", description = "Позволяет добавить пользователя в систему. После регистрации возвращает клиенту пару ключей авторизации: acces в body и refresh в куки.")
    @PostMapping("/register")
    public ResponseEntity<Object> register(@Valid @RequestBody RegisterRequest req) {
        authService.registerUser(req);
        return ResponseEntity.ok().build();
    }

    @Operation(summary = "Эндпоинт подтверждения почты пользователя", description = "Позволяет пользователю \"активировать\" свой аккаунт при переходе по ссылке")
    @GetMapping("/confirm-email")
    public ResponseEntity<?> confirmRegistration(@RequestParam("token") String token) {
        authService.activateUser(token);
        return ResponseEntity.ok().build();
    }

    @Operation(summary = "Повторная отправка сообщения дла активации акканут на почту пользователя", description = "Позволяет пользователю переотправить ссылку на почту для \"активировации\" аккаунта")
    @PostMapping("/resend-confirmation")
    public ResponseEntity<?> resendToken(@RequestParam("email") String email) {
        authService.resendConfirmToken(email);
        return ResponseEntity.ok().build();

    }

    @Operation(summary = "Авторизация пользователей", description = "Позволяет авторизоваться пользователю в системе. После авторизации возвращает клиенту пару ключей авторизации: acces в body и refresh в куки.")
    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String ip = ClientIpUtils.resolve(request);
        String userAgent = request.getHeader("User-Agent");

        AuthServiceResult result = authService.loginUser(loginRequest, ip, userAgent);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, result.getCookie())
                .body(new JwtResponse(result.getAccesToken()));
    }

    @Operation(summary = "Обновление refresh токена авторизации", description = "Позволяет фронту обновить refresh токен пользователя без необходимости повторного входа а аккаунт по истечению времени пребывания авторизованным.")
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@CookieValue(name = "refreshToken", required = false) String refreshToken, HttpServletRequest request) {
        if (refreshToken == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String ip = ClientIpUtils.resolve(request);
        String userAgent = request.getHeader("User-Agent");

        AuthServiceResult result = authService.refreshToken(refreshToken, userAgent, ip);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, result.getCookie())
                .body(new JwtResponse(result.getAccesToken()));
    }

    @Operation(summary = "Переустановка refresh-куки после OAuth2 входа",
               description = "Вызывается фронтом после редиректа соцсети: принимает access-токен, по нему находит пользователя и выдаёт свежую refresh-куку. Нужен потому, что кука из ответа 302 OAuth2 ложится в чужую браузерную партицию (Firefox dFPI) и не доходит до фронта.")
    @PostMapping("/oauth-bootstrap")
    public ResponseEntity<?> oauthBootstrap(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization, HttpServletRequest request) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        String accessToken = authorization.substring(7);
        String ip = ClientIpUtils.resolve(request);
        String userAgent = request.getHeader("User-Agent");

        AuthServiceResult result = authService.oauthBootstrap(accessToken, userAgent, ip);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, result.getCookie())
                .body(new JwtResponse(result.getAccesToken()));
    }

    @Operation(summary = "Выход пользователя из аккаунта", description = "Позволяет пользователю обнулить текущую сессию. Удаляет токен из куки.")
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@CookieValue(name = "refreshToken", required = false) String refreshToken, Principal principal) {
        String userId = principal.getName();
        AuthServiceResult result = authService.logoutUser(userId, refreshToken);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, result.getCookie())
                .build();
    }

    @Operation(summary = "Смена/Восстановление пароля Шаг 1", description = "Принимает почту пользователя и отправляет на неё письмо для восстановления пароля.")
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        authService.createPasswordResetToken(request.getEmail());
        return ResponseEntity.ok().build();
    }

    @Operation(summary = "Смена/Восстановление пароля Шаг 2", description = "Позволяет сменить пароль при наличии токена из письма с почты.")
    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        authService.resetPassword(request.getToken(), request.getNewPassword());
        return ResponseEntity.ok().build();
    }

    @Operation(summary = "Авторизация через Яндекс (мобильное приложение)",
               description = "Принимает access token от Яндекс OAuth и возвращает JWT токены.")
    @PostMapping("/yandex-mobile")
    public ResponseEntity<?> yandexMobile(@RequestBody YandexMobileTokenRequest request, HttpServletRequest httpRequest) {
        String ip = ClientIpUtils.resolve(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        try {
            AuthServiceResult result = yandexAuthService.authenticateMobile(request.getAccessToken(), userAgent, ip);
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, result.getCookie())
                    .body(new JwtResponse(result.getAccesToken()));
        } catch (OAuthEmailAlreadyExistsException e) {
            log.warn("Yandex mobile collision: email {} already registered via another method", e.getEmail());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "code", "EMAIL_EXISTS_LINK_REQUIRED",
                    "message", e.getMessage(),
                    "email", e.getEmail(),
                    "provider", e.getProvider().name(),
                    "providerUserId", e.getProviderUserId()
            ));
        }
    }

    @Operation(summary = "Авторизация через VK ID (мобильное приложение)",
               description = "Принимает код авторизации, codeVerifier, deviceId и state от VK ID SDK (флоу WebView), обменивает код на токены в VK ID Backend и возвращает JWT.")
    @PostMapping("/vk-mobile")
    public ResponseEntity<?> vkMobile(@Valid @RequestBody VkMobileTokenRequest request, HttpServletRequest httpRequest) {
        String ip = ClientIpUtils.resolve(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        try {
            AuthServiceResult result = vkAuthService.authenticateMobile(request.getCode(), request.getCodeVerifier(), request.getDeviceId(), userAgent, ip);
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, result.getCookie())
                    .body(new JwtResponse(result.getAccesToken()));
        } catch (OAuthEmailAlreadyExistsException e) {
            log.warn("VK mobile collision: email {} already registered via another method", e.getEmail());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                    "code", "EMAIL_EXISTS_LINK_REQUIRED",
                    "message", e.getMessage(),
                    "email", e.getEmail(),
                    "provider", e.getProvider().name(),
                    "providerUserId", e.getProviderUserId()
            ));
        }
    }

    @Operation(summary = "Привязка соцсети", description = "Привязывает соцсеть к аккаунту после ввода пароля.")
    @PostMapping("/link-social")
    public ResponseEntity<?> linkSocial(@Valid @RequestBody LinkSocialRequest request, HttpServletRequest httpRequest) {
        String ip = ClientIpUtils.resolve(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        AuthServiceResult result = authService.linkSocialAccount(request, userAgent, ip);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, result.getCookie())
                .body(new JwtResponse(result.getAccesToken()));
    }

    @Operation(summary = "Список активных сессий", description = "Возвращает все активные сессии текущего пользователя")
    @GetMapping("/sessions")
    public ResponseEntity<List<SessionResponse>> getSessions(
            @CookieValue(name = "refreshToken", required = false) String currentRefreshToken,
            Principal principal) {
        UUID userId = UUID.fromString(principal.getName());
        List<SessionResponse> sessions = refreshTokenService.findAllByUserId(userId).stream()
                .map(token -> new SessionResponse(
                        token.getId(),
                        token.getIp(),
                        token.getCity(),
                        token.getUserAgent(),
                        token.getCreatedAt() != null ? token.getCreatedAt().atZone(java.time.ZoneId.systemDefault()).toInstant() : null,
                        token.getExpiryDate(),
                        token.isRememberMe(),
                        token.getToken().equals(currentRefreshToken)
                ))
                .toList();
        return ResponseEntity.ok(sessions);
    }

    @Operation(summary = "Завершить сессию", description = "Завершает конкретную сессию по ID")
    @DeleteMapping("/sessions/{sessionId}")
    public ResponseEntity<Void> deleteSession(
            @PathVariable UUID sessionId,
            @CookieValue(name = "refreshToken", required = false) String currentRefreshToken,
            Principal principal) {
        UUID userId = UUID.fromString(principal.getName());
        refreshTokenService.deleteSessionById(userId, sessionId, currentRefreshToken);
        return ResponseEntity.noContent().build();
    }

    @Operation(summary = "Завершить все сессии кроме текущей", description = "Вы logout из всех устройств кроме текущего")
    @DeleteMapping("/sessions")
    public ResponseEntity<Void> deleteAllSessions(
            @CookieValue(name = "refreshToken", required = false) String currentRefreshToken,
            Principal principal) {
        UUID userId = UUID.fromString(principal.getName());
        if (currentRefreshToken != null) {
            refreshTokenService.deleteByUserIdExceptToken(userId, currentRefreshToken);
        }
        return ResponseEntity.noContent().build();
    }
}