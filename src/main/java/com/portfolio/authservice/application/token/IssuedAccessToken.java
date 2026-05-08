package com.portfolio.authservice.application.token;

import java.time.Instant;
import java.util.List;

public record IssuedAccessToken(
        String accessToken,
        String tokenType,
        String expiresIn,
        String jti,
        Instant issuedAt,
        Instant expiresAt,
        List<String> scopes) {
}
