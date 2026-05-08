package com.portfolio.authservice.common.error;

public class AuditPersistenceException extends RuntimeException {

    public static final String GENERAL_ERROR_RESPONSE_CODE = "5007300";

    private final String responseCode;
    private final String responseMessage;
    private final String reason;

    public AuditPersistenceException(String responseMessage, String reason, Throwable cause) {
        super(reason, cause);
        this.responseCode = GENERAL_ERROR_RESPONSE_CODE;
        this.responseMessage = responseMessage;
        this.reason = reason;
    }

    public String getResponseCode() {
        return responseCode;
    }

    public String getResponseMessage() {
        return responseMessage;
    }

    public String getReason() {
        return reason;
    }
}
