package com.portfolio.authservice.common.error;

public class SnapConflictException extends SnapException {

    public static final String CONFLICT_RESPONSE_CODE = "4097300";

    public SnapConflictException(String responseMessage, String reason) {
        super(CONFLICT_RESPONSE_CODE, responseMessage, reason);
    }
}
