package com.n4d3sh1k4.security_service.controller;

import com.n4d3sh1k4.common.exception.ContentNotFoundException;
import com.n4d3sh1k4.common.exception.TooManyRequestsException;
import com.n4d3sh1k4.common.exception.TokenNotFoundException;
import com.n4d3sh1k4.common.exception.UserAlreadyActivatedException;
import com.n4d3sh1k4.common.exception.UserAlreadyExistsException;
import com.n4d3sh1k4.common.exception.UserNotFoundException;
import com.n4d3sh1k4.security_service.domain.repository.RoleRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import com.n4d3sh1k4.security_service.domain.model.security.RefreshToken;
import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import com.n4d3sh1k4.security_service.exception.OAuthEmailAlreadyExistsException;
import com.n4d3sh1k4.security_service.dto.AuthServiceResult;
import com.n4d3sh1k4.security_service.dto.request_dto.LinkSocialRequest;
import com.n4d3sh1k4.security_service.dto.request_dto.LoginRequest;
import com.n4d3sh1k4.security_service.jwt.JwtProvider;
import com.n4d3sh1k4.security_service.security.UserDetailsServiceImpl;
import com.n4d3sh1k4.security_service.service.AuthService;
import com.n4d3sh1k4.security_service.service.RefreshTokenService;
import com.n4d3sh1k4.security_service.service.YandexAuthService;
import com.n4d3sh1k4.security_service.service.VkAuthService;
import com.n4d3sh1k4.security_service.utils.CookieUtils;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.autoconfigure.web.DataWebAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.context.annotation.Import;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(excludeAutoConfiguration = DataWebAutoConfiguration.class, properties = "app.test.webmvc-config=enabled")
@Import(AuthController.class)
@AutoConfigureMockMvc(addFilters = true)
class AuthControllerTest {

    private static final String USER_ID = "550e8400-e29b-41d4-a716-446655440000";
    private static final String ACCESS_TOKEN = "access-token";
    private static final String REFRESH_COOKIE = "refreshToken=some-refresh; Path=/; HttpOnly";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthenticationManager authenticationManager;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private YandexAuthService yandexAuthService;

    @MockitoBean
    private VkAuthService vkAuthService;

    @MockitoBean
    private RefreshTokenService refreshTokenService;

    @MockitoBean
    private UserRepository userRepository;

    @MockitoBean
    private UserDetailsServiceImpl userDetailsService;

    @MockitoBean
    private JwtProvider jwtProvider;

    @MockitoBean
    private PasswordEncoder passwordEncoder;

    @MockitoBean
    private RoleRepository roleRepository;

    @MockitoBean
    private CookieUtils cookieUtils;

    private String validRegisterJson() {
        return """
                {
                  "email": "user@mail.ru",
                  "password": "Password#4848",
                  "confirmPassword": "Password#4848"
                }
                """;
    }

    @Test
    void register_validRequest_returns200() throws Exception {
        mockMvc.perform(post("/auth/register")
                        .contentType("application/json")
                        .content(validRegisterJson()))
                .andExpect(status().isOk());

        verify(authService).registerUser(any());
    }

    @Test
    void register_duplicateEmail_returns409() throws Exception {
        doThrow(new UserAlreadyExistsException("A user with this email already exists"))
                .when(authService).registerUser(any());

        mockMvc.perform(post("/auth/register")
                        .contentType("application/json")
                        .content(validRegisterJson()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error.code").value("USER_ALREADY_EXISTS"));
    }

    @Test
    void register_weakPassword_returns400() throws Exception {
        String json = """
                {
                  "email": "user@mail.ru",
                  "password": "short",
                  "confirmPassword": "short"
                }
                """;

        mockMvc.perform(post("/auth/register")
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));

        verify(authService, never()).registerUser(any());
    }

    @Test
    void register_mismatchedPasswords_returns400() throws Exception {
        String json = """
                {
                  "email": "user@mail.ru",
                  "password": "Password#4848",
                  "confirmPassword": "Different#123"
                }
                """;

        mockMvc.perform(post("/auth/register")
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));
    }

    @Test
    void register_foreignEmailDomain_returns400() throws Exception {
        String json = """
                {
                  "email": "user@gmail.com",
                  "password": "Password#4848",
                  "confirmPassword": "Password#4848"
                }
                """;

        mockMvc.perform(post("/auth/register")
                        .contentType("application/json")
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));
    }

    @Test
    void confirmEmail_validToken_returns200() throws Exception {
        mockMvc.perform(get("/auth/confirm-email").param("token", "valid-token"))
                .andExpect(status().isOk());

        verify(authService).activateUser("valid-token");
    }

    @Test
    void confirmEmail_unknownToken_returns404() throws Exception {
        doThrow(new TokenNotFoundException("Activate token not found or provided", "NOT_FOUND", HttpStatus.NOT_FOUND))
                .when(authService).activateUser(anyString());

        mockMvc.perform(get("/auth/confirm-email").param("token", "bad-token"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("NOT_FOUND"));
    }

    @Test
    void confirmEmail_expiredToken_returns410() throws Exception {
        doThrow(new TokenNotFoundException("This link is no longer valid.", "LINK_EXPIRED", HttpStatus.GONE))
                .when(authService).activateUser(anyString());

        mockMvc.perform(get("/auth/confirm-email").param("token", "expired-token"))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.error.code").value("LINK_EXPIRED"));
    }

    @Test
    void resendConfirmation_returns200() throws Exception {
        mockMvc.perform(post("/auth/resend-confirmation").param("email", "user@gmail.com"))
                .andExpect(status().isOk());

        verify(authService).resendConfirmToken("user@gmail.com");
    }

    @Test
    void resendConfirmation_unknownEmail_returns404() throws Exception {
        doThrow(new UserNotFoundException("User with this email not found."))
                .when(authService).resendConfirmToken(anyString());

        mockMvc.perform(post("/auth/resend-confirmation").param("email", "ghost@gmail.com"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("USER_NOT_FOUND"));
    }

    @Test
    void resendConfirmation_alreadyActivated_returns409() throws Exception {
        doThrow(new UserAlreadyActivatedException("The account has already been verified"))
                .when(authService).resendConfirmToken(anyString());

        mockMvc.perform(post("/auth/resend-confirmation").param("email", "user@gmail.com"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error.code").value("USER_ALREADY_ACTIVATED"));
    }

    @Test
    void resendConfirmation_tooFast_returns429() throws Exception {
        doThrow(new TooManyRequestsException("Too fast!"))
                .when(authService).resendConfirmToken(anyString());

        mockMvc.perform(post("/auth/resend-confirmation").param("email", "user@gmail.com"))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error.code").value("RATE_LIMIT_EXCEEDED"));
    }

    @Test
    void login_success_returnsAccessTokenAndCookie() throws Exception {
        Authentication authentication = mock(Authentication.class);
        when(authenticationManager.authenticate(any())).thenReturn(authentication);
        when(authService.loginUser(any(LoginRequest.class), any(), any()))
                .thenReturn(new AuthServiceResult(ACCESS_TOKEN, REFRESH_COOKIE));

        mockMvc.perform(post("/auth/login")
                        .contentType("application/json")
                        .content("""
                                {
                                  "email": "user@gmail.com",
                                  "password": "Password#4848",
                                  "rememberMe": false
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, REFRESH_COOKIE))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.accessToken").value(ACCESS_TOKEN))
                .andExpect(jsonPath("$.data.type").value("Bearer"));
    }

    @Test
    void login_wrongCredentials_returns401() throws Exception {
        doThrow(new BadCredentialsException("Bad credentials"))
                .when(authenticationManager).authenticate(any());

        mockMvc.perform(post("/auth/login")
                        .contentType("application/json")
                        .content("""
                                {
                                  "email": "user@gmail.com",
                                  "password": "WrongPassword#1"
                                }
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("AUTH_ERROR"));
    }

    @Test
    void login_notActivatedAccount_returns403() throws Exception {
        doThrow(new DisabledException("Account is disabled"))
                .when(authenticationManager).authenticate(any());

        mockMvc.perform(post("/auth/login")
                        .contentType("application/json")
                        .content("""
                                {
                                  "email": "user@gmail.com",
                                  "password": "Password#4848"
                                }
                                """))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error.code").value("EMAIL_NOT_VERIFIED"));
    }

    @Test
    void login_lockedAccount_returns429() throws Exception {
        doThrow(new LockedException("User is locked"))
                .when(authenticationManager).authenticate(any());

        mockMvc.perform(post("/auth/login")
                        .contentType("application/json")
                        .content("""
                                {
                                  "email": "user@gmail.com",
                                  "password": "Password#4848"
                                }
                                """))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error.code").value("RATE_LIMIT_EXCEEDED"))
                .andExpect(jsonPath("$.error.message").value("Account is locked. Try again later."));
    }

    @Test
    void errorResponseBody_isLoggedWithCodeAndMessage() throws Exception {
        ch.qos.logback.classic.Logger logger = (ch.qos.logback.classic.Logger)
                org.slf4j.LoggerFactory.getLogger(com.n4d3sh1k4.security_service.advice.ErrorResponseLogger.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender =
                new ch.qos.logback.core.read.ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            mockMvc.perform(post("/auth/login")
                            .contentType("application/json")
                            .content("{\"email\": \"\"}"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));
        } finally {
            logger.detachAppender(appender);
        }

        org.junit.jupiter.api.Assertions.assertFalse(appender.list.isEmpty());
        String msg = appender.list.get(0).getFormattedMessage();
        org.junit.jupiter.api.Assertions.assertTrue(
                msg.contains("/auth/login") && msg.contains("400") && msg.contains("VALIDATION_ERROR"),
                "unexpected log line: " + msg);
    }

    @Test
    void refresh_missingCookie_returns401() throws Exception {
        mockMvc.perform(post("/auth/refresh"))
                .andExpect(status().isUnauthorized());

        verify(authService, never()).refreshToken(any(), any(), any());
    }

    @Test
    void refresh_validCookie_returns200() throws Exception {
        when(authService.refreshToken(eq("some-refresh"), any(), any()))
                .thenReturn(new AuthServiceResult(ACCESS_TOKEN, REFRESH_COOKIE));

        mockMvc.perform(post("/auth/refresh").cookie(new Cookie("refreshToken", "some-refresh")))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, REFRESH_COOKIE))
                .andExpect(jsonPath("$.data.accessToken").value(ACCESS_TOKEN));
    }

    @Test
    void refresh_unknownToken_returns404() throws Exception {
        doThrow(new TokenNotFoundException("Refresh token not found or provided.", "REFRESH_TOKEN_NOT_FOUND", HttpStatus.NOT_FOUND))
                .when(authService).refreshToken(anyString(), any(), any());

        mockMvc.perform(post("/auth/refresh").cookie(new Cookie("refreshToken", "unknown")))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("REFRESH_TOKEN_NOT_FOUND"));
    }

    @Test
    void refresh_expiredToken_returns401() throws Exception {
        doThrow(new TokenNotFoundException("Refresh token expired", "REFRESH_TOKEN_EXPIRED", HttpStatus.UNAUTHORIZED))
                .when(authService).refreshToken(anyString(), any(), any());

        mockMvc.perform(post("/auth/refresh").cookie(new Cookie("refreshToken", "expired")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error.code").value("REFRESH_TOKEN_EXPIRED"));
    }

    @Test
    void logout_withCookie_returns200() throws Exception {
        when(authService.logoutUser(USER_ID, "some-refresh"))
                .thenReturn(new AuthServiceResult("refreshToken=; Max-Age=0; Path=/; HttpOnly"));

        mockMvc.perform(post("/auth/logout")
                        .with(user(USER_ID))
                        .cookie(new Cookie("refreshToken", "some-refresh")))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, containsString("Max-Age=0")));
    }

    @Test
    void logout_withoutCookie_returns404() throws Exception {
        doThrow(new ContentNotFoundException("No refresh token provided"))
                .when(authService).logoutUser(eq(USER_ID), isNull());

        mockMvc.perform(post("/auth/logout").with(user(USER_ID)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("NOT_FOUND"));
    }

    @Test
    void forgotPassword_success_returns200() throws Exception {
        mockMvc.perform(post("/auth/forgot-password")
                        .contentType("application/json")
                        .content("{\"email\": \"user@gmail.com\"}"))
                .andExpect(status().isOk());

        verify(authService).createPasswordResetToken("user@gmail.com");
    }

    @Test
    void forgotPassword_unknownEmail_returns404() throws Exception {
        doThrow(new UserNotFoundException("User with this email not found."))
                .when(authService).createPasswordResetToken(anyString());

        mockMvc.perform(post("/auth/forgot-password")
                        .contentType("application/json")
                        .content("{\"email\": \"ghost@gmail.com\"}"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("USER_NOT_FOUND"));
    }

    @Test
    void forgotPassword_invalidEmail_returns400() throws Exception {
        mockMvc.perform(post("/auth/forgot-password")
                        .contentType("application/json")
                        .content("{\"email\": \"not-an-email\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));
    }

    @Test
    void resetPassword_success_returns200() throws Exception {
        mockMvc.perform(post("/auth/reset-password")
                        .contentType("application/json")
                        .content("""
                                {
                                  "token": "reset-token",
                                  "newPassword": "Password#4848"
                                }
                                """))
                .andExpect(status().isOk());

        verify(authService).resetPassword(eq("reset-token"), eq("Password#4848"));
    }

    @Test
    void resetPassword_unknownToken_returns404() throws Exception {
        doThrow(new TokenNotFoundException("Token no found.", "TOKEN_NOT_FOUND", HttpStatus.NOT_FOUND))
                .when(authService).resetPassword(anyString(), anyString());

        mockMvc.perform(post("/auth/reset-password")
                        .contentType("application/json")
                        .content("""
                                {
                                  "token": "bad-token",
                                  "newPassword": "Password#4848"
                                }
                                """))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("TOKEN_NOT_FOUND"));
    }

    @Test
    void resetPassword_expiredToken_returns410() throws Exception {
        doThrow(new TokenNotFoundException("Token expired.", "TOKEN_EXPIRED", HttpStatus.GONE))
                .when(authService).resetPassword(anyString(), anyString());

        mockMvc.perform(post("/auth/reset-password")
                        .contentType("application/json")
                        .content("""
                                {
                                  "token": "expired-token",
                                  "newPassword": "Password#4848"
                                }
                                """))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.error.code").value("TOKEN_EXPIRED"));
    }

    @Test
    void resetPassword_weakPassword_returns400() throws Exception {
        mockMvc.perform(post("/auth/reset-password")
                        .contentType("application/json")
                        .content("""
                                {
                                  "token": "reset-token",
                                  "newPassword": "weak"
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));
    }

    @Test
    void yandexMobile_success_returns200() throws Exception {
        when(yandexAuthService.authenticateMobile(eq("y0_access_token"), any(), any()))
                .thenReturn(new AuthServiceResult(ACCESS_TOKEN, REFRESH_COOKIE));

        mockMvc.perform(post("/auth/yandex-mobile")
                        .contentType("application/json")
                        .content("{\"accessToken\": \"y0_access_token\"}"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.SET_COOKIE, REFRESH_COOKIE))
                .andExpect(jsonPath("$.data.accessToken").value(ACCESS_TOKEN));
    }

    @Test
    void yandexMobile_emailCollision_returns409LinkRequired() throws Exception {
        when(yandexAuthService.authenticateMobile(eq("y0_access_token"), any(), any()))
                .thenThrow(new OAuthEmailAlreadyExistsException("user@example.com", AuthProvider.YANDEX, "123456789"));

        mockMvc.perform(post("/auth/yandex-mobile")
                        .contentType("application/json")
                        .content("{\"accessToken\": \"y0_access_token\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error.code").value("EMAIL_EXISTS_LINK_REQUIRED"))
                .andExpect(jsonPath("$.data.email").value("user@example.com"))
                .andExpect(jsonPath("$.data.provider").value("YANDEX"))
                .andExpect(jsonPath("$.data.providerUserId").value("123456789"));
    }

    @Test
    void vkMobile_emailCollision_returns409LinkRequired() throws Exception {
        when(vkAuthService.authenticateMobile(eq("vk_code"), eq("verifier"), eq("device-1"), any(), any()))
                .thenThrow(new OAuthEmailAlreadyExistsException("user@example.com", AuthProvider.VK, "777"));

        mockMvc.perform(post("/auth/vk-mobile")
                        .contentType("application/json")
                        .content("{\"code\": \"vk_code\", \"codeVerifier\": \"verifier\", \"deviceId\": \"device-1\"}"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.error.code").value("EMAIL_EXISTS_LINK_REQUIRED"))
                .andExpect(jsonPath("$.data.email").value("user@example.com"))
                .andExpect(jsonPath("$.data.provider").value("VK"))
                .andExpect(jsonPath("$.data.providerUserId").value("777"));
    }

    @Test
    void linkSocial_success_returns200() throws Exception {
        when(authService.linkSocialAccount(any(LinkSocialRequest.class), any(), any()))
                .thenReturn(new AuthServiceResult(ACCESS_TOKEN, REFRESH_COOKIE));

        mockMvc.perform(post("/auth/link-social")
                        .contentType("application/json")
                        .content("""
                                {
                                  "email": "user@gmail.com",
                                  "password": "Password#4848",
                                  "provider": "YANDEX",
                                  "providerUserId": "123456789"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.accessToken").value(ACCESS_TOKEN));
    }

    @Test
    void linkSocial_missingProvider_returns400() throws Exception {
        mockMvc.perform(post("/auth/link-social")
                        .contentType("application/json")
                        .content("""
                                {
                                  "email": "user@gmail.com",
                                  "password": "Password#4848",
                                  "providerUserId": "123456789"
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error.code").value("VALIDATION_ERROR"));
    }

    // ---------- sessions ----------

    private static final String SESSION_ID = "650e8400-e29b-41d4-a716-446655440000";
    private static final String OTHER_SESSION_ID = "750e8400-e29b-41d4-a716-446655440000";

    private RefreshToken refreshToken(String id, String tokenValue, String ip) {
        RefreshToken rt = new RefreshToken();
        rt.setId(java.util.UUID.fromString(id));
        rt.setToken(tokenValue);
        rt.setIp(ip);
        rt.setUserAgent("Mozilla/5.0");
        rt.setExpiryDate(java.time.Instant.now().plus(3600, java.time.temporal.ChronoUnit.SECONDS));
        rt.setRememberMe(true);
        rt.setCreatedAt(java.time.LocalDateTime.of(2026, 9, 26, 12, 0));
        return rt;
    }

    @Test
    void getSessions_marksCurrentSessionByCookie() throws Exception {
        when(refreshTokenService.findAllByUserId(java.util.UUID.fromString(USER_ID))).thenReturn(java.util.List.of(
                refreshToken(SESSION_ID, "current-token", "127.0.0.1"),
                refreshToken(OTHER_SESSION_ID, "other-token", "10.0.0.5")));

        mockMvc.perform(get("/auth/sessions")
                        .with(user(USER_ID).roles("USER"))
                        .cookie(new Cookie("refreshToken", "current-token")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.length()").value(2))
                .andExpect(jsonPath("$.data[0].id").value(SESSION_ID))
                .andExpect(jsonPath("$.data[0].ip").value("127.0.0.1"))
                .andExpect(jsonPath("$.data[0].userAgent").value("Mozilla/5.0"))
                .andExpect(jsonPath("$.data[0].rememberMe").value(true))
                .andExpect(jsonPath("$.data[0].current").value(true))
                .andExpect(jsonPath("$.data[1].current").value(false));
    }

    @Test
    void getSessions_withoutCookie_allSessionsNonCurrent() throws Exception {
        when(refreshTokenService.findAllByUserId(java.util.UUID.fromString(USER_ID)))
                .thenReturn(java.util.List.of(refreshToken(SESSION_ID, "t1", "127.0.0.1")));

        mockMvc.perform(get("/auth/sessions").with(user(USER_ID)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data[0].current").value(false));
    }

    @Test
    void deleteSession_passesIdsAndCookieToService() throws Exception {
        mockMvc.perform(delete("/auth/sessions/" + SESSION_ID)
                        .with(user(USER_ID))
                        .cookie(new Cookie("refreshToken", "current-token")))
                .andExpect(status().isNoContent());

        verify(refreshTokenService).deleteSessionById(
                java.util.UUID.fromString(USER_ID),
                java.util.UUID.fromString(SESSION_ID),
                "current-token");
    }

    @Test
    void deleteSession_unknownSession_returns204AndDelegates() throws Exception {
        mockMvc.perform(delete("/auth/sessions/" + OTHER_SESSION_ID)
                        .with(user(USER_ID))
                        .cookie(new Cookie("refreshToken", "current-token")))
                .andExpect(status().isNoContent());

        verify(refreshTokenService).deleteSessionById(
                java.util.UUID.fromString(USER_ID),
                java.util.UUID.fromString(OTHER_SESSION_ID),
                "current-token");
    }

    @Test
    void deleteSession_withoutCookie_passesNullCookieToService() throws Exception {
        mockMvc.perform(delete("/auth/sessions/" + SESSION_ID)
                        .with(user(USER_ID)))
                .andExpect(status().isNoContent());

        verify(refreshTokenService).deleteSessionById(
                java.util.UUID.fromString(USER_ID),
                java.util.UUID.fromString(SESSION_ID),
                null);
    }

    @Test
    void deleteAllSessions_withCookie_revokesExceptCurrent() throws Exception {
        mockMvc.perform(delete("/auth/sessions")
                        .with(user(USER_ID))
                        .cookie(new Cookie("refreshToken", "current-token")))
                .andExpect(status().isNoContent());

        verify(refreshTokenService).deleteByUserIdExceptToken(
                java.util.UUID.fromString(USER_ID), "current-token");
    }

    @Test
    void deleteAllSessions_withoutCookie_doesNotDelete() throws Exception {
        mockMvc.perform(delete("/auth/sessions").with(user(USER_ID)))
                .andExpect(status().isNoContent());

        verify(refreshTokenService, never()).deleteByUserIdExceptToken(any(), any());
    }
}