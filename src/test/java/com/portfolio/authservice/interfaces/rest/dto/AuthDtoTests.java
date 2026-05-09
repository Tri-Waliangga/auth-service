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

    @Test
    void internalSignatureVerifyRequestCanBindPayload() throws Exception {
        String payload = """
                {
                  "clientId": "client-id",
                  "timestamp": "2026-05-07T15:00:00+07:00",
                  "signature": "signature",
                  "stringToSign": "custom-string-to-sign"
                }
                """;

        InternalSignatureVerifyRequest request = objectMapper.readValue(payload, InternalSignatureVerifyRequest.class);

        assertThat(request.clientId()).isEqualTo("client-id");
        assertThat(request.timestamp()).isEqualTo("2026-05-07T15:00:00+07:00");
        assertThat(request.signature()).isEqualTo("signature");
        assertThat(request.stringToSign()).isEqualTo("custom-string-to-sign");
    }

    @Test
    void internalSignatureVerifyRequestRejectsBlankSignature() {
        InternalSignatureVerifyRequest request = new InternalSignatureVerifyRequest(
                "client-id",
                "2026-05-07T15:00:00+07:00",
                " ",
                null);

        assertThat(validator.validate(request)).isNotEmpty();
    }

    @Test
    void signatureAuthGenerateRequestCanBindPayload() throws Exception {
        String payload = """
                {
                  "clientId": "client-id",
                  "timestamp": "2026-05-10T12:00:00+07:00",
                  "privateKeyPem": "private-key"
                }
                """;

        SignatureAuthGenerateRequest request = objectMapper.readValue(payload, SignatureAuthGenerateRequest.class);

        assertThat(request.clientId()).isEqualTo("client-id");
        assertThat(request.timestamp()).isEqualTo("2026-05-10T12:00:00+07:00");
        assertThat(request.privateKeyPem()).isEqualTo("private-key");
    }
}
