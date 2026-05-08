package com.portfolio.authservice.common.error;

public class SignatureVerificationException extends SnapUnauthorizedException {

    public static final String UNAUTHORIZED_RESPONSE_CODE = "4017300";

    public SignatureVerificationException(String responseMessage, String reason) {
        super(UNAUTHORIZED_RESPONSE_CODE, responseMessage, reason);
    }
}
