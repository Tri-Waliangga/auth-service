package com.portfolio.authservice.application.credential;

public class ClientCredentialException extends RuntimeException {

    public static final String UNAUTHORIZED_RESPONSE_CODE = "4017300";

    private final String responseCode;
    private final String responseMessage;
    private final ClientCredentialFailureReason failureReason;

    public ClientCredentialException(String responseMessage, ClientCredentialFailureReason failureReason) {
        super(failureReason.name());
        this.responseCode = UNAUTHORIZED_RESPONSE_CODE;
        this.responseMessage = responseMessage;
        this.failureReason = failureReason;
    }

    public String getResponseCode() {
        return responseCode;
    }

    public String getResponseMessage() {
        return responseMessage;
    }

    public ClientCredentialFailureReason getFailureReason() {
        return failureReason;
    }
}
