package com.portfolio.authservice.interfaces.rest.dto;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

class AuthDtoTests {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void accessTokenB2BRequestCanBindPostmanPayload() throws Exception {
        String payload = """
                {
                  "grantType": "client_credentials",
                  "additionalInfo": {}
                }
                """;

        AccessTokenB2BRequest request = objectMapper.readValue(payload, AccessTokenB2BRequest.class);

        assertThat(request.grantType()).isEqualTo("client_credentials");
        assertThat(request.additionalInfo()).isEmpty();
    }

    @Test
    void accessTokenB2BRequestRejectsBlankGrantType() {
        AccessTokenB2BRequest request = new AccessTokenB2BRequest(" ", null);

        assertThat(validator.validate(request)).isNotEmpty();
    }

    @Test
    void tokenIntrospectionRequestRejectsBlankToken() {
        TokenIntrospectionRequest request = new TokenIntrospectionRequest("");

        assertThat(validator.validate(request)).isNotEmpty();
    }
}
