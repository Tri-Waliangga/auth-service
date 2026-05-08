package com.portfolio.authservice.application.validation;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.portfolio.authservice.application.command.TokenCommand;
import com.portfolio.authservice.common.error.SnapValidationException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

class SnapRequestValidatorTests {

    private static final Instant NOW = Instant.parse("2026-05-07T08:00:00Z");

    private final SnapRequestValidator validator = new SnapRequestValidator(
            Clock.fixed(NOW, ZoneOffset.UTC),
            Duration.ofMinutes(5),
            fallbackResponseCodeMapper());

    @Test
    void acceptsValidAccessTokenRequestWithJsonContentType() {
        TokenCommand command = validCommand("2026-05-07T15:00:00+07:00");

        assertThatCode(() -> validator.validateAccessTokenRequest(command, "application/json"))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsJsonContentTypeWithCharset() {
        TokenCommand command = validCommand("2026-05-07T15:00:00+07:00");

        assertThatCode(() -> validator.validateAccessTokenRequest(command, "application/json;charset=UTF-8"))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsTimestampAtClockSkewBoundary() {
        TokenCommand pastBoundary = validCommand("2026-05-07T14:55:00+07:00");
        TokenCommand futureBoundary = validCommand("2026-05-07T15:05:00+07:00");

        assertThatCode(() -> validator.validateAccessTokenRequest(pastBoundary, "application/json"))
                .doesNotThrowAnyException();
        assertThatCode(() -> validator.validateAccessTokenRequest(futureBoundary, "application/json"))
                .doesNotThrowAnyException();
    }

    @Test
    void rejectsMissingContentTypeAsBadRequest() {
        assertValidationFailure(
                validCommand("2026-05-07T15:00:00+07:00"),
                null,
                SnapRequestValidator.BAD_REQUEST_CODE,
                "Bad Request");
    }

    @Test
    void rejectsInvalidContentTypeAsBadRequest() {
        assertValidationFailure(
                validCommand("2026-05-07T15:00:00+07:00"),
                "text/plain",
                SnapRequestValidator.BAD_REQUEST_CODE,
                "Bad Request");
    }

    @Test
    void rejectsBlankClientIdAsInvalidMandatoryField() {
        assertValidationFailure(
                new TokenCommand(" ", "2026-05-07T15:00:00+07:00", "signature", "client_credentials", null, null, null),
                "application/json",
                SnapRequestValidator.INVALID_MANDATORY_FIELD_CODE,
                "Invalid Mandatory Field X-CLIENT-KEY");
    }

    @Test
    void rejectsBlankTimestampAsInvalidMandatoryField() {
        assertValidationFailure(
                new TokenCommand("client-id", "", "signature", "client_credentials", null, null, null),
                "application/json",
                SnapRequestValidator.INVALID_MANDATORY_FIELD_CODE,
                "Invalid Mandatory Field X-TIMESTAMP");
    }

    @Test
    void rejectsBlankSignatureAsInvalidMandatoryField() {
        assertValidationFailure(
                new TokenCommand("client-id", "2026-05-07T15:00:00+07:00", " ", "client_credentials", null, null, null),
                "application/json",
                SnapRequestValidator.INVALID_MANDATORY_FIELD_CODE,
                "Invalid Mandatory Field X-SIGNATURE");
    }

    @Test
    void rejectsBlankGrantTypeAsInvalidMandatoryField() {
        assertValidationFailure(
                new TokenCommand("client-id", "2026-05-07T15:00:00+07:00", "signature", null, null, null, null),
                "application/json",
                SnapRequestValidator.INVALID_MANDATORY_FIELD_CODE,
                "Invalid Mandatory Field grantType");
    }

    @Test
    void rejectsUnsupportedGrantTypeAsInvalidMandatoryField() {
        assertValidationFailure(
                new TokenCommand("client-id", "2026-05-07T15:00:00+07:00", "signature", "password", null, null, null),
                "application/json",
                SnapRequestValidator.INVALID_MANDATORY_FIELD_CODE,
                "Invalid Mandatory Field grantType");
    }

    @Test
    void rejectsTimestampWithoutTimezoneAsInvalidFieldFormat() {
        assertValidationFailure(
                validCommand("2026-05-07T15:00:00"),
                "application/json",
                SnapRequestValidator.INVALID_FIELD_FORMAT_CODE,
                "Invalid Field Format X-TIMESTAMP");
    }

    @Test
    void rejectsMalformedTimestampAsInvalidFieldFormat() {
        assertValidationFailure(
                validCommand("not-a-timestamp"),
                "application/json",
                SnapRequestValidator.INVALID_FIELD_FORMAT_CODE,
                "Invalid Field Format X-TIMESTAMP");
    }

    @Test
    void rejectsTimestampOlderThanClockSkewAsBadRequest() {
        assertValidationFailure(
                validCommand("2026-05-07T14:54:59+07:00"),
                "application/json",
                SnapRequestValidator.BAD_REQUEST_CODE,
                "Bad Request");
    }

    @Test
    void rejectsTimestampNewerThanClockSkewAsBadRequest() {
        assertValidationFailure(
                validCommand("2026-05-07T15:05:01+07:00"),
                "application/json",
                SnapRequestValidator.BAD_REQUEST_CODE,
                "Bad Request");
    }

    private TokenCommand validCommand(String timestamp) {
        return new TokenCommand(
                "client-id",
                timestamp,
                "signature",
                "client_credentials",
                "127.0.0.1",
                "JUnit",
                "request-id");
    }

    private void assertValidationFailure(
            TokenCommand command,
            String contentType,
            String responseCode,
            String responseMessage) {
        assertThatThrownBy(() -> validator.validateAccessTokenRequest(command, contentType))
                .isInstanceOfSatisfying(SnapValidationException.class, exception -> {
                    org.assertj.core.api.Assertions.assertThat(exception.getResponseCode()).isEqualTo(responseCode);
                    org.assertj.core.api.Assertions.assertThat(exception.getResponseMessage()).isEqualTo(responseMessage);
                    org.assertj.core.api.Assertions.assertThat(exception.getReason()).isNotBlank();
                });
    }

    @SuppressWarnings("unchecked")
    private SnapResponseCodeMapper fallbackResponseCodeMapper() {
        ObjectProvider<ResponseCodeMappingJpaRepository> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        return new SnapResponseCodeMapper(provider);
    }
}
