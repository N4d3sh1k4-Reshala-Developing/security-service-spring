package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.dto.AuthServiceResult;
import com.n4d3sh1k4.security_service.jwt.JwtProvider;
import com.n4d3sh1k4.security_service.utils.CookieUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class YandexAuthService {

    private final RestTemplate restTemplate = new RestTemplate();
    private final UserService userService;
    private final JwtProvider jwtProvider;
    private final CookieUtils cookieUtils;

    public AuthServiceResult authenticateMobile(String yandexAccessToken) {
        Map<String, Object> attributes = fetchYandexUserInfo(yandexAccessToken);

        String email = (String) attributes.get("default_email");
        String firstName = (String) attributes.get("first_name");
        String lastName = (String) attributes.get("last_name");

        User user = userService.processOAuthPostLogin(email.toLowerCase(), firstName, lastName);

        String accessToken = jwtProvider.generateAccessToken(user);
        ResponseCookie refreshTokenCookie = cookieUtils.generateRefreshTokenCookie(user, true);

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