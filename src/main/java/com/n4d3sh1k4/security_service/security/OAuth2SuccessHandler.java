package com.n4d3sh1k4.security_service.security;

import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.exception.OAuthEmailAlreadyExistsException;
import com.n4d3sh1k4.security_service.jwt.JwtProvider;
import com.n4d3sh1k4.security_service.service.UserGeoService;
import com.n4d3sh1k4.security_service.service.UserService;
import com.n4d3sh1k4.security_service.utils.ClientIpUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;
    private final UserService userService;
    private final UserGeoService userGeoService;

    @Value("${app.frontend-url:http://localhost:3000}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(@NonNull HttpServletRequest request,
                                        @NonNull HttpServletResponse response,
                                        @NonNull Authentication authentication) throws IOException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = oauthToken.getPrincipal();

        String registrationId = oauthToken.getAuthorizedClientRegistrationId().toUpperCase();
        AuthProvider provider = AuthProvider.valueOf(registrationId);

        String email = oAuth2User.getAttribute("email");
        if (email == null) {
            email = oAuth2User.getAttribute("default_email");
        }

        if (email == null || email.isBlank()) {
            log.error("OAuth2 login failed: Provider {} did not return an email", provider);
            response.sendRedirect(frontendUrl + "/login?error=email_not_found");
            return;
        }

        String providerUserId = extractProviderUserId(oAuth2User, provider);

        String[] names = extractAndNormalizeNames(oAuth2User);
        String firstName = names[0];
        String lastName = names[1];
        String phone = extractAndNormalizePhone(oAuth2User);

        try {
            User user = userService.processOAuthPostLogin(provider, providerUserId, email, firstName, lastName, phone);

            String ip = ClientIpUtils.resolve(request);

            String city = userGeoService.resolveCity(ip);
            String accessToken = jwtProvider.generateAccessToken(user, city);

            // Refresh-сессию здесь НЕ создаём: кука из ответа 302 не доходит до фронта
            // (Firefox dFPI / cross-context redirect), поэтому фронт вызывает
            // POST /auth/oauth-bootstrap, где и создаётся единственная refresh-сессия.
            // Иначе каждый вход через провайдера плодил бы "мёртвую" вторую сессию.
            String targetUrl = frontendUrl + "/oauth-callback?token=" + accessToken;
            response.sendRedirect(targetUrl);

        } catch (OAuthEmailAlreadyExistsException e) {
            log.warn("OAuth2 collision: Email {} is already registered via another method", e.getEmail());
            String targetUrl = String.format(frontendUrl + "/login?error=email_exists_link_required&email=%s&provider=%s&providerUserId=%s",
                    e.getEmail(), e.getProvider().name(), e.getProviderUserId());
            response.sendRedirect(targetUrl);
        }
    }

    private String extractProviderUserId(OAuth2User oAuth2User, AuthProvider provider) {
        Object rawId = oAuth2User.getAttribute("id");
        if (rawId != null) {
            return rawId.toString();
        }
        return oAuth2User.getName();
    }

    private String[] extractAndNormalizeNames(OAuth2User oAuth2User) {
        // Пытаемся забрать из стандарта OIDC (Т-Банк, Сбер)
        String firstName = oAuth2User.getAttribute("given_name");
        String lastName = oAuth2User.getAttribute("family_name");

        // Если там пусто — значит это Яндекс или старый VK, берем их ключи
        if (firstName == null) firstName = oAuth2User.getAttribute("first_name");
        if (lastName == null) lastName = oAuth2User.getAttribute("last_name");

        // Fallback для экзотики
        if ((firstName == null || firstName.isBlank()) && (lastName == null || lastName.isBlank())) {
            String rawName = oAuth2User.getAttribute("name"); // Имя целиком одной строкой
            if (rawName != null && !rawName.isBlank()) {
                String[] parts = rawName.trim().split("\\s+", 2);
                firstName = parts[0];
                lastName = (parts.length > 1) ? parts[1] : "";
            }
        }

        return new String[]{
                (firstName != null) ? firstName.trim() : "",
                (lastName != null) ? lastName.trim() : ""
        };
    }

    private String extractAndNormalizePhone(OAuth2User oAuth2User) {
        // 1. Пытаемся вытащить хоть по какому-то ключу
        String rawPhone = oAuth2User.getAttribute("phone_number"); // Стандарт OIDC
        if (rawPhone == null) rawPhone = oAuth2User.getAttribute("phone");        // VK
        if (rawPhone == null) rawPhone = oAuth2User.getAttribute("default_phone"); // Яндекс

        if (rawPhone == null || rawPhone.isBlank()) {
            return null;
        }

        // 2. ЖЕСТКАЯ ОЧИСТКА: вырезаем вообще всё, кроме цифр
        // Было: "+7 (911) 123-45-67" -> Стало: "79111234567"
        String cleaned = rawPhone.replaceAll("[^0-9]", "");

        // 3. Приводим российские номера к единому стандарту "79xxxxxxxxx"
        if (cleaned.length() == 11) {
            if (cleaned.startsWith("8")) {
                // Заменяем первую '8' на '7'
                cleaned = "7" + cleaned.substring(1);
            }
        } else if (cleaned.length() == 10 && cleaned.startsWith("9")) {
            // Если провайдер прислал 10 цифр вида "9111234567", подставляем 7 спереди
            cleaned = "7" + cleaned;
        }

        // На выходе ВСЕГДА будет либо чистая строка из 11 цифр, начинающаяся на 7, либо null
        return cleaned;
    }
}