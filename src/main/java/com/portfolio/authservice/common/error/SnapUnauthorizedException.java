package com.portfolio.authservice.common.error;

public class SnapUnauthorizedException extends SnapException {

    public static final String INVALID_TOKEN_RESPONSE_CODE = "4017301";

    public SnapUnauthorizedException(String responseCode, String responseMessage, String reason) {
        super(responseCode, responseMessage, reason);
    }
}
