package com.portfolio.authservice.interfaces.rest.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import java.util.Map;

@Schema(description = "SNAP Access Token B2B request body")
public record AccessTokenB2BRequest(
        @Schema(description = "OAuth grant type. SNAP B2B supports client_credentials.",
                example = "client_credentials")
        @NotBlank String grantType,
        @Schema(description = "Additional request attributes. Keep empty for current B2B token flow.",
                example = "{}")
        Map<String, Object> additionalInfo) {
}
