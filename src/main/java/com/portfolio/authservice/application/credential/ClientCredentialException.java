package com.portfolio.authservice.application.credential;

import com.portfolio.authservice.common.error.SnapUnauthorizedException;

public class ClientCredentialException extends SnapUnauthorizedException {

    public static final String UNAUTHORIZED_RESPONSE_CODE = "4017300";

    private final ClientCredentialFailureReason failureReason;

    public ClientCredentialException(String responseMessage, ClientCredentialFailureReason failureReason) {
        super(UNAUTHORIZED_RESPONSE_CODE, responseMessage, failureReason.name());
        this.failureReason = failureReason;
    }

    public ClientCredentialFailureReason getFailureReason() {
        return failureReason;
    }
}
