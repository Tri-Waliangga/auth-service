package com.portfolio.authservice.interfaces.rest.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;
import java.util.Map;

@Schema(description = "Internal token introspection response")
public record TokenIntrospectionResponse(
        @Schema(description = "Whether the token is active", example = "true")
        boolean active,
        @Schema(description = "Client identifier when active", example = "962489e9-de5d-4eb7-92a4-b07d44d64bf4")
        String clientId,
        @Schema(description = "Space-delimited granted scopes", example = "openid snap:auth:token")
        String scope,
        @Schema(description = "Token type", example = "Bearer")
        String tokenType,
        @Schema(description = "Token expiry timestamp", example = "2026-05-11T16:15:00Z")
        Instant expiresAt,
        @Schema(description = "Token issuance timestamp", example = "2026-05-11T16:00:00Z")
        Instant issuedAt,
        @Schema(description = "Token subject", example = "962489e9-de5d-4eb7-92a4-b07d44d64bf4")
        String subject,
        @Schema(description = "Additional token metadata", example = "{\"jti\":\"00000000-0000-4000-8000-000000000000\"}")
        Map<String, Object> additionalInfo) {
}
