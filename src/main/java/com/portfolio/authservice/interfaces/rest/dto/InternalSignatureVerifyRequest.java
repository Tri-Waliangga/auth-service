package com.portfolio.authservice.interfaces.rest.dto;

import jakarta.validation.constraints.NotBlank;

public record InternalSignatureVerifyRequest(
        @NotBlank String clientId,
        @NotBlank String timestamp,
        @NotBlank String signature,
        String stringToSign) {
}
