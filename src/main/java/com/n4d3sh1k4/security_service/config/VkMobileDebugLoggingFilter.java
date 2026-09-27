package com.n4d3sh1k4.security_service.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

// Временный debug-фильтр диагностики VK-логина (тело запроса/ответа /auth/vk-mobile) — удалить после разбора.
@Slf4j
@Component
public class VkMobileDebugLoggingFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (request.getRequestURI() == null || !request.getRequestURI().endsWith("/auth/vk-mobile")) {
            filterChain.doFilter(request, response);
            return;
        }

        ContentCachingRequestWrapper wrappedRequest = new ContentCachingRequestWrapper(request, 100_000);
        ContentCachingResponseWrapper wrappedResponse = new ContentCachingResponseWrapper(response);
        try {
            filterChain.doFilter(wrappedRequest, wrappedResponse);
        } finally {
            wrappedResponse.copyBodyToResponse();
            String requestBody = new String(wrappedRequest.getContentAsByteArray(), StandardCharsets.UTF_8);
            String responseBody = new String(wrappedResponse.getContentAsByteArray(), StandardCharsets.UTF_8);
            log.debug("[VK-DEBUG] {} {} request body={}", request.getMethod(), request.getRequestURI(), requestBody);
            log.debug("[VK-DEBUG] {} {} response status={} body={}", request.getMethod(), request.getRequestURI(),
                    wrappedResponse.getStatus(), responseBody);
        }
    }
}
