package com.portfolio.authservice.interfaces.rest.dto;

import jakarta.validation.constraints.NotBlank;

public record TokenIntrospectionRequest(
        @NotBlank String token) {
}
