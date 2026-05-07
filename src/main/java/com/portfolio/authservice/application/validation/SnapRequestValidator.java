package com.portfolio.authservice.application.validation;

import com.portfolio.authservice.application.command.TokenCommand;
import com.portfolio.authservice.common.error.SnapValidationException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class SnapRequestValidator {

    public static final String BAD_REQUEST_CODE = "4007300";
    public static final String INVALID_FIELD_FORMAT_CODE = "4007301";
    public static final String INVALID_MANDATORY_FIELD_CODE = "4007302";
    public static final String CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials";

    private static final Duration DEFAULT_CLOCK_SKEW = Duration.ofMinutes(5);

    private final Clock clock;
    private final Duration clockSkew;
    private final SnapResponseCodeMapper responseCodeMapper;

    @Autowired
    public SnapRequestValidator(Clock clock, SnapResponseCodeMapper responseCodeMapper) {
        this(clock, DEFAULT_CLOCK_SKEW, responseCodeMapper);
    }

    SnapRequestValidator(Clock clock, Duration clockSkew, SnapResponseCodeMapper responseCodeMapper) {
        this.clock = clock;
        this.clockSkew = clockSkew;
        this.responseCodeMapper = responseCodeMapper;
    }

    public void validateAccessTokenRequest(TokenCommand command, String contentType) {
        validateContentType(contentType);

        if (command == null) {
            throwInvalidMandatoryField("request");
        }

        validateMandatoryField(command.clientId(), "X-CLIENT-KEY");
        validateMandatoryField(command.timestamp(), "X-TIMESTAMP");
        validateMandatoryField(command.signature(), "X-SIGNATURE");
        validateMandatoryField(command.grantType(), "grantType");
        validateGrantType(command.grantType());
        validateTimestamp(command.timestamp());
    }

    private void validateContentType(String contentType) {
        if (!StringUtils.hasText(contentType)) {
            throwBadRequest("Content-Type is required");
        }

        try {
            MediaType mediaType = MediaType.parseMediaType(contentType);
            if (!MediaType.APPLICATION_JSON.isCompatibleWith(mediaType)) {
                throwBadRequest("Content-Type must be application/json");
            }
        } catch (IllegalArgumentException exception) {
            throwBadRequest("Content-Type is malformed");
        }
    }

    private void validateMandatoryField(String value, String fieldName) {
        if (!StringUtils.hasText(value)) {
            throwInvalidMandatoryField(fieldName);
        }
    }

    private void validateGrantType(String grantType) {
        if (!CLIENT_CREDENTIALS_GRANT_TYPE.equals(grantType)) {
            throwInvalidMandatoryField("grantType");
        }
    }

    private void validateTimestamp(String timestamp) {
        Instant requestTime;
        try {
            requestTime = OffsetDateTime.parse(timestamp, DateTimeFormatter.ISO_OFFSET_DATE_TIME).toInstant();
        } catch (DateTimeParseException exception) {
            throwInvalidFieldFormat("X-TIMESTAMP");
            return;
        }

        Instant now = clock.instant();
        if (requestTime.isBefore(now.minus(clockSkew)) || requestTime.isAfter(now.plus(clockSkew))) {
            throwBadRequest("X-TIMESTAMP is outside allowed clock skew");
        }
    }

    private void throwBadRequest(String reason) {
        throw new SnapValidationException(
                BAD_REQUEST_CODE,
                responseCodeMapper.resolveMessage(BAD_REQUEST_CODE),
                reason);
    }

    private void throwInvalidFieldFormat(String fieldName) {
        throw new SnapValidationException(
                INVALID_FIELD_FORMAT_CODE,
                responseCodeMapper.resolveMessage(INVALID_FIELD_FORMAT_CODE, fieldName),
                "Invalid field format: " + fieldName);
    }

    private void throwInvalidMandatoryField(String fieldName) {
        throw new SnapValidationException(
                INVALID_MANDATORY_FIELD_CODE,
                responseCodeMapper.resolveMessage(INVALID_MANDATORY_FIELD_CODE, fieldName),
                "Invalid mandatory field: " + fieldName);
    }
}
