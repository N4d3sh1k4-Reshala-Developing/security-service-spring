package com.n4d3sh1k4.security_service.controller;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Тестовая конфигурация для {@code @WebMvcTest}-слайсов. Цепочка создаётся только
 * когда задана property {@code app.test.webmvc-config=enabled} (класс остаётся
 * primary-источником для слайсов, а в полных {@code @SpringBootTest}-контекстах
 * бин не регистрируется — иначе было бы две SecurityFilterChain "any request":
 * реальная из {@code SecurityConfig} + тестовая).
 */
@SpringBootConfiguration
@EnableWebSecurity
@ComponentScan(basePackages = {
        "com.n4d3sh1k4.common.advice"
})
public class WebMvcTestConfiguration {

    @Bean
    @ConditionalOnProperty(name = "app.test.webmvc-config", havingValue = "enabled", matchIfMissing = false)
    public SecurityFilterChain testSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }
}