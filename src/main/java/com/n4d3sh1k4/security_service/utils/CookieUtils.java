package com.n4d3sh1k4.security_service.utils;

import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.service.RefreshTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class CookieUtils {

    private final String cookieName = "refreshToken";

    private final RefreshTokenService refreshTokenService;

    @Value("${cookie.secure.state}")
    private Boolean cookieSecureState;

    @Value("${token.refresh.isremember.ttl}")
    private Duration refreshTTLisRemember;

    @Value("${token.refresh.noremember.ttl}")
    private Duration refreshTTLnoRemember;

    public CookieUtils(RefreshTokenService refreshTokenService) {
        this.refreshTokenService = refreshTokenService;
    }

    public ResponseCookie generateRefreshTokenCookie(User user, boolean rememberMe, String userAgent, String ip, String city) {
        long maxAge = rememberMe ? refreshTTLisRemember.getSeconds() : refreshTTLnoRemember.getSeconds();

        return ResponseCookie.from(cookieName, refreshTokenService.createRefreshToken(user, rememberMe, userAgent, ip, city).getToken())
                .httpOnly(true)
                .secure(cookieSecureState)
                .sameSite(cookieSecureState ? "None" : "Lax")
                .path("/")
                .maxAge(maxAge)
                .build();
    }

    public ResponseCookie getCleanRefreshTokenCookie() {
        return ResponseCookie.from(cookieName, "")
                .httpOnly(true)
                .secure(cookieSecureState)
                .sameSite(cookieSecureState ? "None" : "Lax")
                .path("/")
                .maxAge(0)
                .build();
    }
}