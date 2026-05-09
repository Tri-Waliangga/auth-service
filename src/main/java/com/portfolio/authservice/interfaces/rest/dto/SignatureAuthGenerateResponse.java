package com.portfolio.authservice.interfaces.rest.dto;

import java.util.Map;

public record SignatureAuthGenerateResponse(
        String signature,
        String stringToSign,
        String algorithm,
        Map<String, Object> additionalInfo) {
}
