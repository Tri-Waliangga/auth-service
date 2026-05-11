package com.portfolio.authservice.interfaces.rest.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Internal SNAP signature verification request")
public record InternalSignatureVerifyRequest(
        @Schema(description = "Client identifier", example = "962489e9-de5d-4eb7-92a4-b07d44d64bf4")
        @NotBlank String clientId,
        @Schema(description = "SNAP timestamp used in the signature", example = "2026-05-11T16:00:00Z")
        @NotBlank String timestamp,
        @Schema(description = "Base64-encoded SHA256withRSA signature", example = "base64-rsa-signature")
        @NotBlank String signature,
        @Schema(description = "Optional explicit string to verify. Defaults to clientId|timestamp when blank.",
                example = "962489e9-de5d-4eb7-92a4-b07d44d64bf4|2026-05-11T16:00:00Z")
        String stringToSign) {
}
