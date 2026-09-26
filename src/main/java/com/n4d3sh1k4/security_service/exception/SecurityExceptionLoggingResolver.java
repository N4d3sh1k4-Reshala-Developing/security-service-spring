package com.n4d3sh1k4.security_service.exception;

import com.n4d3sh1k4.common.exception.BaseException;
import com.n4d3sh1k4.security_service.utils.ClientIpUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SecurityExceptionLoggingResolver implements HandlerExceptionResolver {

    @Override
    public ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        if (isExpected(ex)) {
            return null;
        }
        log.error("Unhandled exception on {} {} from ip={}, ua={}",
                request.getMethod(),
                request.getRequestURI(),
                ClientIpUtils.resolve(request),
                request.getHeader("User-Agent"),
                ex);
        return null;
    }

    private boolean isExpected(Exception ex) {
        return ex instanceof BaseException
                || ex instanceof MethodArgumentNotValidException
                || ex instanceof BadCredentialsException
                || ex instanceof DisabledException;
    }
}
