package com.portfolio.authservice.interfaces.rest.dto;

import java.util.Map;

public record SnapErrorResponse(
        String responseCode,
        String responseMessage,
        Map<String, Object> additionalInfo) {
}
