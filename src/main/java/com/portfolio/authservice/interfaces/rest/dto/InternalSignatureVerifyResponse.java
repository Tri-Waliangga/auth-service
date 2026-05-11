package com.portfolio.authservice.interfaces.rest.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.Map;

@Schema(description = "Internal SNAP signature verification response")
public record InternalSignatureVerifyResponse(
        @Schema(description = "Whether the signature is valid", example = "true")
        boolean valid,
        @Schema(description = "SNAP response code", example = "2007300")
        String responseCode,
        @Schema(description = "SNAP response message", example = "Successful")
        String responseMessage,
        @Schema(description = "Failure reason when invalid", example = "INVALID_SIGNATURE")
        String failureReason,
        @Schema(description = "Additional response attributes", example = "{}")
        Map<String, Object> additionalInfo) {
}
