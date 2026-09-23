package com.n4d3sh1k4.security_service.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import java.util.List;

@Configuration
public class OAuth2ClientConfig {

    @Value("${YANDEX_CLIENT_ID:5e58d1a8f2f141df8928574f01b6e152}")
    private String yandexClientId;

    @Value("${YANDEX_CLIENT_SECRET:637fb18431784d97be2afc104e2786b9}")
    private String yandexClientSecret;

    @Value("${VK_CLIENT_ID:54657062}")
    private String vkClientId;

    @Value("${VK_CLIENT_SECRET:d07afc96d07afc96d07afc96e7d338fcb0dd07ad07afc96ba3ba982bc64d9ab003d4939}")
    private String vkClientSecret;

    @Value("${app.oauth2.redirect-uri:http://localhost:8180/api/v0/login/oauth2/code/{registrationId}}")
    private String redirectUri;

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(List.of(
                yandexRegistration(),
                vkRegistration()
        ));
    }

    private ClientRegistration yandexRegistration() {
        return ClientRegistration.withRegistrationId("yandex")
                .clientId(yandexClientId)
                .clientSecret(yandexClientSecret)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(redirectUri)
                .scope("login:email", "login:info")
                .clientName("Yandex")
                .authorizationUri("https://oauth.yandex.ru/authorize")
                .tokenUri("https://oauth.yandex.ru/token")
                .userInfoUri("https://login.yandex.ru/info")
                .userNameAttributeName("id")
                .build();
    }

    private ClientRegistration vkRegistration() {
        return ClientRegistration.withRegistrationId("vk")
                .clientId(vkClientId)
                .clientSecret(vkClientSecret)
                // По доке для конфиденциальных приложений передается client_secret в POST теле (service_token)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(redirectUri)
                .scope("vkid.personal_info", "email") // Запрашиваем стандартный базовый скоуп из доки
                .clientName("VK")
                .authorizationUri("https://id.vk.ru/authorize")
                .tokenUri("https://id.vk.ru/oauth2/auth")
                .userInfoUri("https://id.vk.ru/oauth2/user_info")
                .userNameAttributeName("user_id") // В новом ответе user_info лежит объект "user" с полем "user_id"
                .clientSettings(ClientRegistration.ClientSettings.builder()
                        .requireProofKey(true) // Обязательно для PKCE
                        .build())
                .build();
    }
}