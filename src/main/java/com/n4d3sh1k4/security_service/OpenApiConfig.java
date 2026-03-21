package com.n4d3sh1k4.security_service;


import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("UCust API")
                        .description("Personal Internet Marketer")
                        .version("0.0.1")
                        .contact(new Contact()
                                .name("Mihail Krivosheev")
                                .url("https://github.com/NEXUSPROGECT")))

                .servers(List.of(
                        new Server()
                                .url("https://thunderobot911.tail5f28aa.ts.net/apivTest")
                                .description("Production (Tailscale)"),
                        new Server()
                                .url("http://localhost:8080/apivTest")
                                .description("Local Environment")
                ))

                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
                .components(new Components()
                        .addSecuritySchemes("bearerAuth", new SecurityScheme()
                                .name("bearerAuth")
                                .type(SecurityScheme.Type.HTTP)
                                .scheme("bearer")
                                .bearerFormat("JWT")));
    }
}