package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.common.exception.BaseException;
import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.dto.AuthServiceResult;
import com.n4d3sh1k4.security_service.jwt.JwtProvider;
import com.n4d3sh1k4.security_service.utils.CookieUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class VkAuthService {

    private static final String VK_TOKEN_URI = "https://id.vk.ru/oauth2/auth";
    private static final String VK_USER_INFO_URI = "https://id.vk.ru/oauth2/user_info";

    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${VK_CLIENT_ID:54657062}")
    private String vkClientId;

    @Value("${VK_CLIENT_SECRET:d07afc96d07afc96d07afc96e7d338fcb0dd07ad07afc96ba3ba982bc64d9ab003d4939}")
    private String vkClientSecret;

    private final UserService userService;
    private final JwtProvider jwtProvider;
    private final CookieUtils cookieUtils;
    private final UserGeoService userGeoService;

    public AuthServiceResult authenticateMobile(String code, String codeVerifier, String deviceId, String userAgent, String ip) {
        String accessToken = exchangeCodeForAccessToken(code, codeVerifier, deviceId);

        Map<String, Object> vkUserAttributes = fetchVkUserInfo(accessToken, deviceId);

        String providerUserId = String.valueOf(vkUserAttributes.get("user_id"));
        String email = (String) vkUserAttributes.get("email");
        if (email == null || email.isBlank()) {
            log.error("VK mobile login failed: VK ID did not return an email for user {}", providerUserId);
            throw new BaseException("VK ID did not return an email", "EMAIL_NOT_FOUND", HttpStatus.BAD_REQUEST);
        }

        String firstName = (String) vkUserAttributes.get("first_name");
        String lastName = (String) vkUserAttributes.get("last_name");
        String phone = normalizePhone((String) vkUserAttributes.get("phone"));

        User user = userService.processOAuthPostLogin(AuthProvider.VK, providerUserId, email, firstName, lastName, phone);

        String city = userGeoService.resolveCity(ip);
        String accessTokenOut = jwtProvider.generateAccessToken(user, city);
        ResponseCookie refreshTokenCookie = cookieUtils.generateRefreshTokenCookie(user, true, userAgent, ip, city);

        log.info("VK mobile login succeeded for user {}", email);
        return new AuthServiceResult(accessTokenOut, refreshTokenCookie.toString());
    }

    /**
     * Меняет код авторизации на ATv2 в VK ID Backend.
     * В отличие от web-флоу (PKCE хранится в серверной сессии Spring Security),
     * здесь code_verifier приходит от мобильного приложения и передаётся как есть.
     */
    private String exchangeCodeForAccessToken(String code, String codeVerifier, String deviceId) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("client_id", vkClientId);
        form.add("client_secret", vkClientSecret);
        form.add("code", code);
        form.add("code_verifier", codeVerifier);
        if (deviceId != null && !deviceId.isBlank()) {
            form.add("device_id", deviceId);
        }

        RequestEntity<MultiValueMap<String, String>> requestEntity = RequestEntity
                .post(VK_TOKEN_URI)
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form);

        try {
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    requestEntity, new ParameterizedTypeReference<Map<String, Object>>() {});
            Map<String, Object> body = response.getBody();
            if (body == null || body.get("access_token") == null) {
                throw new BaseException("VK ID did not return an access token", "VK_TOKEN_EXCHANGE_FAILED", HttpStatus.BAD_REQUEST);
            }
            return String.valueOf(body.get("access_token"));
        } catch (RestClientException ex) {
            log.error("VK mobile token exchange failed: {}", ex.getMessage(), ex);
            throw new BaseException("VK ID token exchange failed: " + ex.getMessage(), "VK_TOKEN_EXCHANGE_FAILED", HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * VK ID требует POST https://id.vk.ru/oauth2/user_info с client_id и access_token
     * в теле (application/x-www-form-urlencoded) и отдаёт ответ вложенно:
     * {"user": {"user_id": "...", "first_name": "...", "last_name": "...", "email": "...", ...}}.
     * Если токен был получен по мобильному флоу с device_id, тот же device_id нужен и здесь.
     */
    private Map<String, Object> fetchVkUserInfo(String accessToken, String deviceId) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", vkClientId);
        form.add("access_token", accessToken);
        if (deviceId != null && !deviceId.isBlank()) {
            form.add("device_id", deviceId);
        }

        RequestEntity<MultiValueMap<String, String>> requestEntity = RequestEntity
                .post(VK_USER_INFO_URI)
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form);

        try {
            ResponseEntity<Map<String, Object>> response = restTemplate.exchange(
                    requestEntity, new ParameterizedTypeReference<Map<String, Object>>() {});
            Map<String, Object> attributes = extractVkUserAttributes(response.getBody());
            if (attributes == null) {
                throw new BaseException("Unexpected user info response structure from VK ID", "VK_USER_INFO_FAILED", HttpStatus.BAD_REQUEST);
            }
            return attributes;
        } catch (RestClientException ex) {
            log.error("VK mobile user info request failed: {}", ex.getMessage(), ex);
            throw new BaseException("VK ID user info request failed: " + ex.getMessage(), "VK_USER_INFO_FAILED", HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * Распаковывает тело ответа в плоскую карту с 'user_id' на верхнем уровне:
     * 1) новый формат VK ID {"user": {...}}
     * 2) legacy формат {"response": [{...}]}
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> extractVkUserAttributes(Map<String, Object> body) {
        if (body == null) {
            return null;
        }
        if (body.get("user") instanceof Map<?, ?> user) {
            return flatCopy((Map<String, Object>) user);
        }
        if (body.get("response") instanceof List<?> responseList
                && !responseList.isEmpty()
                && responseList.get(0) instanceof Map<?, ?> firstEntry) {
            return flatCopy((Map<String, Object>) firstEntry);
        }
        return null;
    }

    private Map<String, Object> flatCopy(Map<?, ?> source) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            if (entry.getKey() instanceof String key) {
                result.put(key, entry.getValue());
            }
        }
        return result;
    }

    /**
     * Приводим телефон VK ID к единому стандарту "79xxxxxxxxx" (то же правило, что в web-флоу).
     */
    private String normalizePhone(String rawPhone) {
        if (rawPhone == null || rawPhone.isBlank()) {
            return null;
        }

        String cleaned = rawPhone.replaceAll("[^0-9]", "");

        if (cleaned.length() == 11 && cleaned.startsWith("8")) {
            cleaned = "7" + cleaned.substring(1);
        } else if (cleaned.length() == 10 && cleaned.startsWith("9")) {
            cleaned = "7" + cleaned;
        }

        return cleaned;
    }
}