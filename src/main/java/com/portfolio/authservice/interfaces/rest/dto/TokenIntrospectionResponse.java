package com.portfolio.authservice.interfaces.rest.dto;

import java.time.Instant;
import java.util.Map;

public record TokenIntrospectionResponse(
        boolean active,
        String clientId,
        String scope,
        String tokenType,
        Instant expiresAt,
        Instant issuedAt,
        String subject,
        Map<String, Object> additionalInfo) {
}
