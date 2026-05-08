package com.portfolio.authservice.interfaces.rest.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.Map;

public record InternalSignatureVerifyRequest(
        @NotBlank String clientId,
        @NotBlank String httpMethod,
        @NotBlank String endpointPath,
        String accessToken,
        Map<String, Object> body) {
}
