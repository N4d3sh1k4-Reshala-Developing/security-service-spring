package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.common.exception.BaseException;
import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.dto.AuthServiceResult;
import com.n4d3sh1k4.security_service.dto.SocialProfile;
import com.n4d3sh1k4.security_service.jwt.JwtProvider;
import com.n4d3sh1k4.security_service.utils.CookieUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class YandexAuthService {

    private final RestTemplate restTemplate = new RestTemplate();
    private final UserService userService;
    private final JwtProvider jwtProvider;
    private final CookieUtils cookieUtils;
    private final UserGeoService userGeoService;

    /**
     * Проверяет свежий access token Яндекса и возвращает профиль провайдера.
     * Это единственный источник providerUserId: клиентский ID не принимается.
     */
    public SocialProfile resolveProfile(String accessToken) {
        Map<String, Object> attributes = fetchYandexUserInfo(accessToken);

        String id = (String) attributes.get("id");
        if (id == null || id.isBlank()) {
            log.error("Yandex info did not return a user id");
            throw new BaseException("Yandex did not return a user id", "YANDEX_USER_INFO_FAILED", HttpStatus.BAD_REQUEST);
        }

        String email = (String) attributes.get("default_email");

        return new SocialProfile(
                id,
                email == null ? null : email.toLowerCase(),
                (String) attributes.get("first_name"),
                (String) attributes.get("last_name"),
                (String) attributes.get("phone")
        );
    }

    public AuthServiceResult authenticateMobile(String yandexAccessToken, String userAgent, String ip) {
        SocialProfile profile = resolveProfile(yandexAccessToken);

        String id = profile.providerUserId();
        String email = profile.email();
        if (email == null || email.isBlank()) {
            log.error("Yandex mobile login failed: Yandex did not return an email for user {}", id);
            throw new BaseException("Yandex did not return an email", "EMAIL_NOT_FOUND", HttpStatus.BAD_REQUEST);
        }

        User user = userService.processOAuthPostLogin(AuthProvider.YANDEX, id, email, profile.firstName(), profile.lastName(), profile.phone());

        String city = userGeoService.resolveCity(ip);
        String accessToken = jwtProvider.generateAccessToken(user, city);
        ResponseCookie refreshTokenCookie = cookieUtils.generateRefreshTokenCookie(user, true, userAgent, ip, city);

        log.info("Yandex mobile login succeeded: userId={}, email={}", user.getId(), email.toLowerCase());
        return new AuthServiceResult(accessToken, refreshTokenCookie.toString());
    }

    private Map fetchYandexUserInfo(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return restTemplate.exchange(
            "https://login.yandex.ru/info?format=json",
            HttpMethod.GET,
            new HttpEntity<>(headers),
            Map.class
        ).getBody();
    }
}