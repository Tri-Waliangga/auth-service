package com.portfolio.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private static final String[] OPENAPI_ENDPOINTS = {
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html"
    };

    private final InternalApiKeyAuthenticationFilter internalApiKeyAuthenticationFilter;
    private final Environment environment;

    public SecurityConfig(
            InternalApiKeyAuthenticationFilter internalApiKeyAuthenticationFilter,
            Environment environment) {
        this.internalApiKeyAuthenticationFilter = internalApiKeyAuthenticationFilter;
        this.environment = environment;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/actuator/health").permitAll()
                        .requestMatchers(HttpMethod.POST, "/cashup/v1.0/access-token/b2b").permitAll()
                        .requestMatchers(HttpMethod.POST, developmentUtilityPath()).access((authentication, context) ->
                                new org.springframework.security.authorization.AuthorizationDecision(developmentUtilityEnabled()))
                        .requestMatchers(OPENAPI_ENDPOINTS).permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(internalApiKeyAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    private String developmentUtilityPath() {
        return "/cashup/v1.0/utilities/signature-auth";
    }

    private boolean developmentUtilityEnabled() {
        for (String activeProfile : environment.getActiveProfiles()) {
            if ("dev".equals(activeProfile) || "local".equals(activeProfile)) {
                return true;
            }
        }
        return false;
    }
}
