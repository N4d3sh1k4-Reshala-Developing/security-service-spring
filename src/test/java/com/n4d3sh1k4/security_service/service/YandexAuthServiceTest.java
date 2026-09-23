package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.dto.AuthServiceResult;
import com.n4d3sh1k4.security_service.jwt.JwtProvider;
import com.n4d3sh1k4.security_service.utils.CookieUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class YandexAuthServiceTest {

    @Mock
    private RestTemplate restTemplate;

    @Mock
    private UserService userService;

    @Mock
    private JwtProvider jwtProvider;

    @Mock
    private CookieUtils cookieUtils;

    @Mock
    private UserGeoService userGeoService;

    private YandexAuthService yandexAuthService;

    @BeforeEach
    void setUp() {
        yandexAuthService = new YandexAuthService(userService, jwtProvider, cookieUtils, userGeoService);
        ReflectionTestUtils.setField(yandexAuthService, "restTemplate", restTemplate);
    }

    @Test
    void authenticateMobile_fetchesUserInfoProcessesOAuthAndReturnsTokens() {
        when(restTemplate.exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(Map.class)))
                .thenReturn(ResponseEntity.ok(Map.of(
                        "id", "ya-123",
                        "default_email", "User@Example.com",
                        "first_name", "Иван",
                        "last_name", "Петров",
                        "phone", "+79990000000"
                )));

        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("user@example.com");
        when(userService.processOAuthPostLogin(
                AuthProvider.YANDEX, "ya-123", "user@example.com", "Иван", "Петров", "+79990000000"))
                .thenReturn(user);
        when(jwtProvider.generateAccessToken(eq(user), any())).thenReturn("access-token");
        when(cookieUtils.generateRefreshTokenCookie(eq(user), eq(true), eq(null), eq(null), any()))
                .thenReturn(ResponseCookie.from("refreshToken", "refresh-value").path("/").build());

        AuthServiceResult result = yandexAuthService.authenticateMobile("yandex-access-token", null, null);

        verify(restTemplate).exchange(
                eq("https://login.yandex.ru/info?format=json"),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(Map.class));
        verify(userService).processOAuthPostLogin(
                AuthProvider.YANDEX, "ya-123", "user@example.com", "Иван", "Петров", "+79990000000");
        assertThat(result.getAccesToken()).isEqualTo("access-token");
        assertThat(result.getCookie()).isEqualTo(
                ResponseCookie.from("refreshToken", "refresh-value").path("/").build().toString());
    }
}