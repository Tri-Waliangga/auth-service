package com.portfolio.authservice.common.error;

public class SnapGeneralException extends SnapException {

    public static final String GENERAL_ERROR_RESPONSE_CODE = "5007300";

    public SnapGeneralException(String responseMessage, String reason) {
        super(GENERAL_ERROR_RESPONSE_CODE, responseMessage, reason);
    }

    public SnapGeneralException(String responseMessage, String reason, Throwable cause) {
        super(GENERAL_ERROR_RESPONSE_CODE, responseMessage, reason, cause);
    }
}
