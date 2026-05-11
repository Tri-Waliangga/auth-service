package com.portfolio.authservice.interfaces.rest.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Local/dev-only signature generation request")
public record SignatureAuthGenerateRequest(
        @Schema(description = "Client identifier. Can also be supplied through X-CLIENT-KEY.",
                example = "962489e9-de5d-4eb7-92a4-b07d44d64bf4")
        String clientId,
        @Schema(description = "SNAP timestamp. Can also be supplied through X-TIMESTAMP.",
                example = "2026-05-11T16:00:00Z")
        String timestamp,
        @Schema(description = "PKCS#8 RSA private key PEM for local/dev testing only. Never use production keys.",
                example = "-----BEGIN PRIVATE KEY-----\\nFAKE_LOCAL_TEST_KEY\\n-----END PRIVATE KEY-----")
        String privateKeyPem) {
}
