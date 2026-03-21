package com.n4d3sh1k4.security_service.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Component
@Slf4j
public class InternalUserFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String userId = request.getHeader("X-User-Id");
        String rolesHeader = request.getHeader("X-User-Roles");

        if (userId != null) {
            // Превращаем строку ролей "ROLE_USER,ROLE_ADMIN" в список Authority
            List<SimpleGrantedAuthority> authorities = Arrays.stream(rolesHeader.split(","))
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());

            // Создаем объект аутентификации. Пароль нам не нужен (null)
            UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(userId, null, authorities);

            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // Кладем в контекст Спринга
            SecurityContextHolder.getContext().setAuthentication(auth);
            log.debug("Internal auth set for user: {}", userId);
        }

        filterChain.doFilter(request, response);
    }
}
