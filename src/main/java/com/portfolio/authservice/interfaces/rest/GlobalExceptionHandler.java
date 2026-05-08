package com.portfolio.authservice.interfaces.rest;

import com.portfolio.authservice.common.error.SnapException;
import com.portfolio.authservice.common.response.SnapResponseMapper;
import com.portfolio.authservice.interfaces.rest.dto.SnapErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingRequestHeaderException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
    private static final String INVALID_MANDATORY_FIELD_CODE = "4007302";
    private static final String GENERAL_ERROR_CODE = "5007300";

    private final SnapResponseMapper responseMapper;

    public GlobalExceptionHandler(SnapResponseMapper responseMapper) {
        this.responseMapper = responseMapper;
    }

    @ExceptionHandler(SnapException.class)
    public ResponseEntity<SnapErrorResponse> handleSnap(SnapException exception, HttpServletRequest request) {
        ResponseEntity<SnapErrorResponse> response =
                responseMapper.errorResponse(exception.getResponseCode(), exception.getResponseMessage());
        logSnapException(request, response, exception);
        return response;
    }

    @ExceptionHandler({
            ConstraintViolationException.class,
            HttpMessageNotReadableException.class,
            MethodArgumentNotValidException.class,
            MissingRequestHeaderException.class,
            MissingServletRequestParameterException.class
    })
    public ResponseEntity<SnapErrorResponse> handleInvalidMandatoryField(
            Exception exception,
            HttpServletRequest request) {
        ResponseEntity<SnapErrorResponse> response = responseMapper.errorResponse(INVALID_MANDATORY_FIELD_CODE);
        logFrameworkException(request, response, exception, "INVALID_MANDATORY_FIELD");
        return response;
    }

    @ExceptionHandler({
            HttpRequestMethodNotSupportedException.class,
            NoHandlerFoundException.class,
            NoResourceFoundException.class
    })
    public ResponseEntity<SnapErrorResponse> handleUnsupportedFrameworkError(
            Exception exception,
            HttpServletRequest request) {
        ResponseEntity<SnapErrorResponse> response = responseMapper.errorResponse(GENERAL_ERROR_CODE);
        logFrameworkException(request, response, exception, "UNSUPPORTED_FRAMEWORK_ERROR");
        return response;
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<SnapErrorResponse> handleUnexpected(Exception exception, HttpServletRequest request) {
        ResponseEntity<SnapErrorResponse> response = responseMapper.errorResponse(GENERAL_ERROR_CODE);
        SnapErrorResponse body = response.getBody();
        log.error(
                "snap_error requestId={} method={} path={} status={} responseCode={} exceptionClass={} reason={}",
                requestId(request),
                method(request),
                path(request),
                response.getStatusCode().value(),
                body == null ? GENERAL_ERROR_CODE : body.responseCode(),
                exception.getClass().getName(),
                "UNEXPECTED_ERROR");
        return response;
    }

    private void logSnapException(
            HttpServletRequest request,
            ResponseEntity<SnapErrorResponse> response,
            SnapException exception) {
        SnapErrorResponse body = response.getBody();
        log.warn(
                "snap_error requestId={} method={} path={} status={} responseCode={} exceptionClass={} reason={}",
                requestId(request),
                method(request),
                path(request),
                response.getStatusCode().value(),
                body == null ? exception.getResponseCode() : body.responseCode(),
                exception.getClass().getName(),
                safeReason(exception.getReason()));
    }

    private void logFrameworkException(
            HttpServletRequest request,
            ResponseEntity<SnapErrorResponse> response,
            Exception exception,
            String reason) {
        SnapErrorResponse body = response.getBody();
        log.warn(
                "snap_error requestId={} method={} path={} status={} responseCode={} exceptionClass={} reason={}",
                requestId(request),
                method(request),
                path(request),
                response.getStatusCode().value(),
                body == null ? GENERAL_ERROR_CODE : body.responseCode(),
                exception.getClass().getName(),
                reason);
    }

    private String requestId(HttpServletRequest request) {
        Object requestId = request.getAttribute(RequestCorrelationFilter.REQUEST_ID_ATTRIBUTE);
        if (requestId instanceof String value && !value.isBlank()) {
            return value;
        }
        return "-";
    }

    private String method(HttpServletRequest request) {
        return request.getMethod();
    }

    private String path(HttpServletRequest request) {
        return request.getRequestURI();
    }

    private String safeReason(String reason) {
        if (reason == null || reason.isBlank()) {
            return "-";
        }
        return reason.replaceAll("[^A-Za-z0-9_:\\-. ]", "_");
    }
}
