package com.portfolio.authservice.common.error;

public class TokenMetadataPersistenceException extends SnapGeneralException {

    public static final String GENERAL_ERROR_RESPONSE_CODE = "5007300";

    public TokenMetadataPersistenceException(String responseMessage, String reason, Throwable cause) {
        super(responseMessage, reason, cause);
    }
}
