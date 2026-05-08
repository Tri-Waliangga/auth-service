package com.portfolio.authservice.interfaces.rest;

import com.portfolio.authservice.application.credential.ClientCredentialException;
import com.portfolio.authservice.common.error.AuditPersistenceException;
import com.portfolio.authservice.common.error.SignatureVerificationException;
import com.portfolio.authservice.common.error.SnapValidationException;
import com.portfolio.authservice.common.error.TokenMetadataPersistenceException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.interfaces.rest.dto.SnapErrorResponse;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String INVALID_MANDATORY_FIELD_CODE = "4007302";
    private static final String GENERAL_ERROR_CODE = "5007300";

    private final SnapResponseCodeMapper responseCodeMapper;

    public GlobalExceptionHandler(SnapResponseCodeMapper responseCodeMapper) {
        this.responseCodeMapper = responseCodeMapper;
    }

    @ExceptionHandler(SnapValidationException.class)
    public ResponseEntity<SnapErrorResponse> handleSnapValidation(SnapValidationException exception) {
        return error(exception.getResponseCode(), exception.getResponseMessage());
    }

    @ExceptionHandler(ClientCredentialException.class)
    public ResponseEntity<SnapErrorResponse> handleClientCredential(ClientCredentialException exception) {
        return error(exception.getResponseCode(), exception.getResponseMessage());
    }

    @ExceptionHandler(SignatureVerificationException.class)
    public ResponseEntity<SnapErrorResponse> handleSignature(SignatureVerificationException exception) {
        return error(exception.getResponseCode(), exception.getResponseMessage());
    }

    @ExceptionHandler(TokenMetadataPersistenceException.class)
    public ResponseEntity<SnapErrorResponse> handleTokenMetadata(TokenMetadataPersistenceException exception) {
        return error(exception.getResponseCode(), exception.getResponseMessage());
    }

    @ExceptionHandler(AuditPersistenceException.class)
    public ResponseEntity<SnapErrorResponse> handleAudit(AuditPersistenceException exception) {
        return error(exception.getResponseCode(), exception.getResponseMessage());
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<SnapErrorResponse> handleUnreadableMessage() {
        return error(
                INVALID_MANDATORY_FIELD_CODE,
                responseCodeMapper.resolveMessage(INVALID_MANDATORY_FIELD_CODE, "request"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<SnapErrorResponse> handleUnexpected() {
        return error(GENERAL_ERROR_CODE, responseCodeMapper.resolvePublicMessage(GENERAL_ERROR_CODE));
    }

    private ResponseEntity<SnapErrorResponse> error(String responseCode, String responseMessage) {
        return ResponseEntity
                .status(httpStatus(responseCode))
                .body(new SnapErrorResponse(responseCode, responseMessage, Map.of()));
    }

    private HttpStatus httpStatus(String responseCode) {
        try {
            return HttpStatus.valueOf(Integer.parseInt(responseCode.substring(0, 3)));
        } catch (RuntimeException exception) {
            return HttpStatus.INTERNAL_SERVER_ERROR;
        }
    }
}
