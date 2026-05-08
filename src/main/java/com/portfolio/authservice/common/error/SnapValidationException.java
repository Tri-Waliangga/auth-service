package com.portfolio.authservice.common.error;

public class SnapValidationException extends SnapException {

    public SnapValidationException(String responseCode, String responseMessage, String reason) {
        super(responseCode, responseMessage, reason);
    }
}
