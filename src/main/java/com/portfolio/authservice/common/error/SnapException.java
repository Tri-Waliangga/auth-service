package com.portfolio.authservice.common.error;

public abstract class SnapException extends RuntimeException {

    private final String responseCode;
    private final String responseMessage;
    private final String reason;

    protected SnapException(String responseCode, String responseMessage, String reason) {
        super(reason);
        this.responseCode = responseCode;
        this.responseMessage = responseMessage;
        this.reason = reason;
    }

    protected SnapException(String responseCode, String responseMessage, String reason, Throwable cause) {
        super(reason, cause);
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
