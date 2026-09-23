package com.n4d3sh1k4.security_service.config;


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
                        .title("Security Service API")
                        .description("Responsible for secure manipulation of user accounts.")
                        .version("0.3.0")
                        .contact(new Contact()
                                .name("Mihail Krivosheev")
                                .url("https://github.com/NEXUSPROGECT")))

                .servers(List.of(
                        new Server()
                                .url("https://api.ucust.n4d3sh1k4.site/api/v0")
                                .description("Production"),
                        new Server()
                                .url("http://localhost:8100/api/v0")
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