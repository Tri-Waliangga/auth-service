package com.portfolio.authservice.common.error;

public class SnapForbiddenException extends SnapException {

    public static final String FORBIDDEN_RESPONSE_CODE = "4037300";

    public SnapForbiddenException(String responseMessage, String reason) {
        super(FORBIDDEN_RESPONSE_CODE, responseMessage, reason);
    }
}
