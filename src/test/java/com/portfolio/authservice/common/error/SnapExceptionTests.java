package com.portfolio.authservice.common.error;

import static org.assertj.core.api.Assertions.assertThat;

import com.portfolio.authservice.application.credential.ClientCredentialException;
import com.portfolio.authservice.application.credential.ClientCredentialFailureReason;
import org.junit.jupiter.api.Test;

class SnapExceptionTests {

    @Test
    void snapValidationExceptionExposesResponseFields() {
        SnapValidationException exception = new SnapValidationException(
                "4007302",
                "Invalid Mandatory Field X-CLIENT-KEY",
                "Invalid mandatory field: X-CLIENT-KEY");

        assertThat(exception.getResponseCode()).isEqualTo("4007302");
        assertThat(exception.getResponseMessage()).isEqualTo("Invalid Mandatory Field X-CLIENT-KEY");
        assertThat(exception.getReason()).isEqualTo("Invalid mandatory field: X-CLIENT-KEY");
    }

    @Test
    void snapUnauthorizedExceptionSupportsInvalidTokenCode() {
        SnapUnauthorizedException exception = new SnapUnauthorizedException(
                SnapUnauthorizedException.INVALID_TOKEN_RESPONSE_CODE,
                "Invalid Token (B2B)",
                "TOKEN_EXPIRED");

        assertThat(exception.getResponseCode()).isEqualTo("4017301");
        assertThat(exception.getResponseMessage()).isEqualTo("Invalid Token (B2B)");
        assertThat(exception.getReason()).isEqualTo("TOKEN_EXPIRED");
    }

    @Test
    void forbiddenConflictAndGeneralExceptionsExposeResponseFields() {
        assertThat(new SnapForbiddenException("Forbidden", "NO_SCOPE").getResponseCode()).isEqualTo("4037300");
        assertThat(new SnapConflictException("Conflict", "REPLAY").getResponseCode()).isEqualTo("4097300");
        assertThat(new SnapGeneralException("General Error", "UNEXPECTED").getResponseCode()).isEqualTo("5007300");
    }

    @Test
    void existingSpecializedExceptionsPreserveAccessors() {
        ClientCredentialException credentialException = new ClientCredentialException(
                "Unauthorized",
                ClientCredentialFailureReason.CLIENT_NOT_FOUND);
        SignatureVerificationException signatureException = new SignatureVerificationException(
                "Unauthorized",
                "INVALID_SIGNATURE");
        TokenMetadataPersistenceException metadataException = new TokenMetadataPersistenceException(
                "General Error",
                "TOKEN_METADATA_SAVE_FAILED",
                new RuntimeException("db"));
        AuditPersistenceException auditException = new AuditPersistenceException(
                "General Error",
                "API_AUDIT_LOG_SAVE_FAILED",
                new RuntimeException("db"));

        assertThat(credentialException).isInstanceOf(SnapUnauthorizedException.class);
        assertThat(credentialException.getFailureReason()).isEqualTo(ClientCredentialFailureReason.CLIENT_NOT_FOUND);
        assertThat(signatureException).isInstanceOf(SnapUnauthorizedException.class);
        assertThat(signatureException.getReason()).isEqualTo("INVALID_SIGNATURE");
        assertThat(metadataException).isInstanceOf(SnapGeneralException.class);
        assertThat(metadataException.getReason()).isEqualTo("TOKEN_METADATA_SAVE_FAILED");
        assertThat(auditException).isInstanceOf(SnapGeneralException.class);
        assertThat(auditException.getReason()).isEqualTo("API_AUDIT_LOG_SAVE_FAILED");
    }
}
