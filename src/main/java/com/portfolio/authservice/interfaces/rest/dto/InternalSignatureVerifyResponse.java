package com.portfolio.authservice.interfaces.rest.dto;

import java.util.Map;

public record InternalSignatureVerifyResponse(
        boolean valid,
        String responseCode,
        String responseMessage,
        String failureReason,
        Map<String, Object> additionalInfo) {
}
