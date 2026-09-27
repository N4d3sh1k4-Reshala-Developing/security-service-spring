package com.n4d3sh1k4.security_service.advice;

import com.n4d3sh1k4.common.dto.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.MethodParameter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

@Slf4j
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class ErrorResponseLogger implements ResponseBodyAdvice<Object> {

    @Override
    public boolean supports(MethodParameter returnType, Class<? extends HttpMessageConverter<?>> converterType) {
        return true;
    }

    @Override
    public Object beforeBodyWrite(Object body, MethodParameter returnType, MediaType selectedContentType,
                                  Class<? extends HttpMessageConverter<?>> selectedConverterType,
                                  ServerHttpRequest request, ServerHttpResponse response) {
        int status = 0;
        if (response instanceof ServletServerHttpResponse servletResponse) {
            status = servletResponse.getServletResponse().getStatus();
        }
        boolean envelopeError = body instanceof ApiResponse<?> api && !api.success();
        if (status < 400 && !envelopeError) {
            return body;
        }

        String code = "-";
        String message = "-";
        if (body instanceof ApiResponse<?> api && api.error() != null) {
            code = api.error().code();
            message = api.error().message();
        }

        String line = "{} {} -> {} code={} message={}";
        if (status >= 500) {
            log.error(line, request.getMethod(), request.getURI().getPath(), status, code, message);
        } else {
            log.warn(line, request.getMethod(), request.getURI().getPath(), status, code, message);
        }
        return body;
    }
}
