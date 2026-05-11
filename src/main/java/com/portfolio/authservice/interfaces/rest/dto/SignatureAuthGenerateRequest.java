package com.portfolio.authservice.interfaces.rest.dto;

public record SignatureAuthGenerateRequest(
        String clientId,
        String timestamp,
        String privateKeyPem) {
}
