package com.n4d3sh1k4.security_service.utils;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

public final class ClientIpUtils {

    private ClientIpUtils() {
    }

    /**
     * Извлекает реальный IP клиента из заголовков прокси.
     * Порядок: X-Forwarded-For (первый в списке) → X-Real-IP → remoteAddr.
     * На проде: nginx stream → nginx http → Spring Cloud Gateway, поэтому
     * без учёта обоих заголовков мы получаем 127.0.0.1 вместо реального IP.
     */
    public static String resolve(HttpServletRequest request) {
        String forwardedFor = firstHeaderValue(request.getHeader("X-Forwarded-For"));
        if (forwardedFor != null) {
            return forwardedFor;
        }
        String realIp = firstHeaderValue(request.getHeader("X-Real-IP"));
        if (realIp != null) {
            return realIp;
        }
        return request.getRemoteAddr();
    }

    private static String firstHeaderValue(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String first = value.split(",")[0].trim();
        return first.isEmpty() ? null : first;
    }
}