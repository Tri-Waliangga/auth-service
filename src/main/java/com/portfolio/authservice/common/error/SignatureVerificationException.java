package com.portfolio.authservice.common.error;

public class SignatureVerificationException extends RuntimeException {

    public static final String UNAUTHORIZED_RESPONSE_CODE = "4017300";

    private final String responseCode;
    private final String responseMessage;
    private final String reason;

    public SignatureVerificationException(String responseMessage, String reason) {
        super(reason);
        this.responseCode = UNAUTHORIZED_RESPONSE_CODE;
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
