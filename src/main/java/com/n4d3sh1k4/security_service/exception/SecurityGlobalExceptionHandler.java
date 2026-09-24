package com.n4d3sh1k4.security_service.exception;

import com.n4d3sh1k4.common.dto.ApiResponse;
import com.n4d3sh1k4.security_service.utils.ClientIpUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityGlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGeneralException(Exception ex, HttpServletRequest request) {
        log.error("Unhandled exception on {} {} from ip={}, ua={}",
                request.getMethod(),
                request.getRequestURI(),
                ClientIpUtils.resolve(request),
                request.getHeader("User-Agent"),
                ex);
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiResponse.error("INTERNAL_SERVER_ERROR", "Server error " + ex.getMessage()));
    }
}