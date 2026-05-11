package com.portfolio.authservice.interfaces.rest.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.Map;

@Schema(description = "SNAP error response envelope")
public record SnapErrorResponse(
        @Schema(description = "SNAP response code", example = "4007302")
        String responseCode,
        @Schema(description = "SNAP response message", example = "Invalid Mandatory Field X-SIGNATURE")
        String responseMessage,
        @Schema(description = "Additional error attributes", example = "{}")
        Map<String, Object> additionalInfo) {
}
