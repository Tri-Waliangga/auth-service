package com.portfolio.authservice.interfaces.rest.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.Map;

@Schema(description = "SNAP Access Token B2B response")
public record AccessTokenB2BResponse(
        @Schema(description = "SNAP response code", example = "2007300")
        String responseCode,
        @Schema(description = "SNAP response message", example = "Successful")
        String responseMessage,
        @Schema(description = "JWT bearer access token", example = "eyJhbGciOiJSUzI1NiJ9.fake-token")
        String accessToken,
        @Schema(description = "Token type", example = "Bearer")
        String tokenType,
        @Schema(description = "Token lifetime in seconds", example = "900")
        String expiresIn,
        @Schema(description = "Additional response attributes", example = "{}")
        Map<String, Object> additionalInfo) {
}
