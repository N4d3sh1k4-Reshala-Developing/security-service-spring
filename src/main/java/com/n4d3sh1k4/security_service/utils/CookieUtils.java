package com.n4d3sh1k4.security_service.utils;

import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.service.RefreshTokenService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtils {

    private final String cookieName = "refreshToken";

    private final RefreshTokenService refreshTokenService;

    @Value("${cookie.secure.state}")
    private Boolean cookieSecureState;

    public CookieUtils(RefreshTokenService refreshTokenService) {
        this.refreshTokenService = refreshTokenService;
    }

    public ResponseCookie generateRefreshTokenCookie(User user) {
        return ResponseCookie.from(cookieName, refreshTokenService.createRefreshToken(user).getToken())
                .httpOnly(true)
                .secure(cookieSecureState)
                .sameSite("None")
                .path("/")
                .maxAge(30 * 24 * 60 * 60) // 30 дней
                .sameSite("Lax")
                .build();
    }

    public ResponseCookie getCleanRefreshTokenCookie() {
        return ResponseCookie.from(cookieName, "")
                .path("/")
                .maxAge(0) // Удаляет куку у клиента
                .build();
    }
}