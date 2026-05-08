package com.portfolio.authservice.interfaces.rest.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.Map;

public record AccessTokenB2BRequest(
        @NotBlank String grantType,
        Map<String, Object> additionalInfo) {
}
