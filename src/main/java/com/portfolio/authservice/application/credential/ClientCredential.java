package com.portfolio.authservice.application.credential;

import java.util.List;

public record ClientCredential(
        Long apiClientId,
        String clientId,
        String merchantCode,
        String channelId,
        Integer tokenTtlSeconds,
        String publicKeyPem,
        String publicKeyAlgorithm,
        String publicKeyId,
        List<String> scopes) {
}
