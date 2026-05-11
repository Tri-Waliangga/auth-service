package com.portfolio.authservice.interfaces.rest.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.Map;

@Schema(description = "Local/dev-only signature generation response")
public record SignatureAuthGenerateResponse(
        @Schema(description = "Base64-encoded SHA256withRSA signature", example = "base64-rsa-signature")
        String signature,
        @Schema(description = "String that was signed", example = "962489e9-de5d-4eb7-92a4-b07d44d64bf4|2026-05-11T16:00:00Z")
        String stringToSign,
        @Schema(description = "Signature algorithm", example = "SHA256withRSA")
        String algorithm,
        @Schema(description = "Additional response attributes", example = "{}")
        Map<String, Object> additionalInfo) {
}
