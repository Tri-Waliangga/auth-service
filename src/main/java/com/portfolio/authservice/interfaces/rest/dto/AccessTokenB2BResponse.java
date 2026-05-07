package com.portfolio.authservice.interfaces.rest.dto;

import java.util.Map;

public record AccessTokenB2BResponse(
        String responseCode,
        String responseMessage,
        String accessToken,
        String tokenType,
        String expiresIn,
        Map<String, Object> additionalInfo) {
}
