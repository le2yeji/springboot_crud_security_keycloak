package com.kt.edu.thirdproject.common.runner;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeycloakAdminConfig {

    @Bean
    public Keycloak keycloakAdmin() {
        return KeycloakBuilder.builder()
                .serverUrl("http://211.43.12.238:30777")
                .realm("master")
                .username("admin")
                .password("New1234!")
                .clientId("admin-cli")
                .build();
    }
}
