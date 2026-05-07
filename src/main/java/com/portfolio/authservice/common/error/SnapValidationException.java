package com.portfolio.authservice.common.error;

public class SnapValidationException extends RuntimeException {

    private final String responseCode;
    private final String responseMessage;
    private final String reason;

    public SnapValidationException(String responseCode, String responseMessage, String reason) {
        super(reason);
        this.responseCode = responseCode;
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
