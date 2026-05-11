package com.portfolio.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

    private static final String ACCESS_TOKEN_ENDPOINT = "/cashup/v1.0/access-token/b2b";
    private static final String DEVELOPMENT_UTILITY_ENDPOINT = "/cashup/v1.0/utilities/signature-auth";
    private static final String INTERNAL_ENDPOINTS = "/internal/**";

    private static final String[] OPS_ENDPOINTS = {
            "/actuator/health",
            "/actuator/prometheus"
    };

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
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, OPS_ENDPOINTS).permitAll()
                        .requestMatchers(HttpMethod.POST, ACCESS_TOKEN_ENDPOINT).permitAll()
                        .requestMatchers(INTERNAL_ENDPOINTS).hasRole("INTERNAL")
                        .requestMatchers(HttpMethod.POST, DEVELOPMENT_UTILITY_ENDPOINT).access((authentication, context) ->
                                new AuthorizationDecision(developmentUtilityEnabled()))
                        .requestMatchers(OPENAPI_ENDPOINTS).permitAll()
                        .anyRequest().denyAll())
                .addFilterBefore(internalApiKeyAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
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
