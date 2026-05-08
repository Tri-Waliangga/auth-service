package com.portfolio.authservice.interfaces.rest;

import com.portfolio.authservice.common.error.SnapException;
import com.portfolio.authservice.common.response.SnapResponseMapper;
import com.portfolio.authservice.interfaces.rest.dto.SnapErrorResponse;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String INVALID_MANDATORY_FIELD_CODE = "4007302";
    private static final String GENERAL_ERROR_CODE = "5007300";

    private final SnapResponseMapper responseMapper;

    public GlobalExceptionHandler(SnapResponseMapper responseMapper) {
        this.responseMapper = responseMapper;
    }

    @ExceptionHandler(SnapException.class)
    public ResponseEntity<SnapErrorResponse> handleSnap(SnapException exception) {
        return responseMapper.errorResponse(exception.getResponseCode(), exception.getResponseMessage());
    }

    @ExceptionHandler({
            ConstraintViolationException.class,
            HttpMessageNotReadableException.class,
            MethodArgumentNotValidException.class,
            MissingServletRequestParameterException.class
    })
    public ResponseEntity<SnapErrorResponse> handleInvalidMandatoryField() {
        return responseMapper.errorResponse(INVALID_MANDATORY_FIELD_CODE);
    }

    @ExceptionHandler({
            HttpRequestMethodNotSupportedException.class,
            NoHandlerFoundException.class,
            NoResourceFoundException.class
    })
    public ResponseEntity<SnapErrorResponse> handleUnsupportedFrameworkError() {
        return responseMapper.errorResponse(GENERAL_ERROR_CODE);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<SnapErrorResponse> handleUnexpected() {
        return responseMapper.errorResponse(GENERAL_ERROR_CODE);
    }
}
