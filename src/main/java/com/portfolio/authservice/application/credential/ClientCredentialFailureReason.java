package com.portfolio.authservice.application.credential;

public enum ClientCredentialFailureReason {
    CLIENT_NOT_FOUND,
    CLIENT_INACTIVE,
    REMOTE_IP_MISSING,
    IP_POLICY_MISSING,
    IP_POLICY_INVALID,
    IP_NOT_ALLOWED,
    PUBLIC_KEY_UNAVAILABLE,
    NO_ACTIVE_SCOPE
}
