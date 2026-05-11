package com.portfolio.authservice.interfaces.rest.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Internal token introspection request")
public record TokenIntrospectionRequest(
        @Schema(description = "Access token to introspect", example = "eyJhbGciOiJSUzI1NiJ9.fake-token")
        @NotBlank String token) {
}
