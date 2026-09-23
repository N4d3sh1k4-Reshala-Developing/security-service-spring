package com.n4d3sh1k4.security_service.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;

/**
 * Best-effort определение города по IP клиента для claim'а "city" в JWT.
 * Никогда не бросает исключений: при любой ошибке (таймаут, приватный IP,
 * неизвестный ответ) возвращает null — логин не должен падать из-за гео.
 */
@Slf4j
@Service
public class UserGeoService {

    private final RestTemplate restTemplate = restTemplate();
    private final String apiUrl;

    public UserGeoService(@Value("${app.geo.api-url:http://ip-api.com/json/{ip}?lang=ru&fields=status,country,city}") String apiUrl) {
        this.apiUrl = apiUrl;
    }

    /**
     * Возвращает название города для переданного IP либо {@code null},
     * если определить город не удалось (локальный адрес, таймаут, ошибка).
     */
    public String resolveCity(String ip) {
        String normalized = normalizeIp(ip);
        if (normalized == null || normalized.isBlank() || isLocalAddress(normalized)) {
            return null;
        }

        try {
            IpApiResponse response = restTemplate.getForObject(apiUrl, IpApiResponse.class, normalized);
            if (response == null || response.status() == null || !response.status().equals("success")) {
                log.debug("Geo lookup for {} returned non-success status", normalized);
                return null;
            }
            String city = response.city();
            if (city == null || city.isBlank()) {
                log.debug("Geo lookup for {} returned no city", normalized);
                return null;
            }
            return city.trim();
        } catch (Exception e) {
            log.debug("Geo lookup failed for {}: {}", normalized, e.getMessage());
            return null;
        }
    }

    private static String normalizeIp(String ip) {
        if (ip == null || ip.isBlank()) {
            return null;
        }
        // X-Forwarded-For может прийти списком "клиент, прокси1, ..." — берём первого клиента.
        String first = ip.split(",")[0].trim();
        return first.isEmpty() ? null : first;
    }

    private static boolean isLocalAddress(String ip) {
        if (ip.equals("::1") || ip.equals("localhost")) {
            return true;
        }
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            // IPv6 без ::1 — считаем внешним, пробуем спросить гео-сервис.
            return false;
        }
        try {
            int a = Integer.parseInt(parts[0]);
            int b = Integer.parseInt(parts[1]);
            return a == 10
                    || a == 127
                    || (a == 192 && b == 168)
                    || (a == 172 && b >= 16 && b <= 31)
                    || a == 0
                    || (a == 100 && b >= 64 && b <= 127)
                    || (a == 169 && b == 254);
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static RestTemplate restTemplate() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(1));
        factory.setReadTimeout(Duration.ofSeconds(1));
        return new RestTemplate(factory);
    }

    public record IpApiResponse(String status, String country, String city) {
    }
}