package com.portfolio.authservice.application.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.portfolio.authservice.application.audit.AuditService;
import com.portfolio.authservice.application.command.TokenCommand;
import com.portfolio.authservice.application.credential.ClientCredential;
import com.portfolio.authservice.application.credential.ClientCredentialService;
import com.portfolio.authservice.application.validation.SnapRequestValidator;
import com.portfolio.authservice.common.error.AuditPersistenceException;
import com.portfolio.authservice.common.error.SignatureVerificationException;
import com.portfolio.authservice.common.error.SnapForbiddenException;
import com.portfolio.authservice.common.error.SnapValidationException;
import com.portfolio.authservice.common.error.TokenMetadataPersistenceException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.common.response.SnapResponseMapper;
import com.portfolio.authservice.domain.port.SignatureVerifier;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import com.portfolio.authservice.interfaces.rest.dto.AccessTokenB2BResponse;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessResourceFailureException;

class TokenApplicationServiceTests {

    private SnapRequestValidator requestValidator;
    private ClientCredentialService clientCredentialService;
    private SignatureVerifier signatureVerifier;
    private JwtTokenService jwtTokenService;
    private AuditService auditService;
    private TokenApplicationService service;

    @BeforeEach
    void setUp() {
        requestValidator = mock(SnapRequestValidator.class);
        clientCredentialService = mock(ClientCredentialService.class);
        signatureVerifier = mock(SignatureVerifier.class);
        jwtTokenService = mock(JwtTokenService.class);
        auditService = mock(AuditService.class);
        service = new TokenApplicationService(
                requestValidator,
                clientCredentialService,
                signatureVerifier,
                jwtTokenService,
                auditService,
                responseCodeMapper(),
                new SnapResponseMapper(responseCodeMapper()));
    }

    @Test
    void validCommandIssuesTokenAndAuditsSuccess() {
        TokenCommand command = command();
        ClientCredential credential = credential();
        IssuedAccessToken token = issuedToken();
        when(clientCredentialService.loadActiveClientCredential("client-id", "10.10.10.10"))
                .thenReturn(credential);
        when(signatureVerifier.verifyAuthSignature("client-id", "2026-04-30T10:00:00+07:00", "signature", credential))
                .thenReturn(true);
        when(jwtTokenService.issueAccessToken(credential)).thenReturn(token);

        AccessTokenB2BResponse response = service.issueB2BToken(command, "application/json");

        assertThat(response.responseCode()).isEqualTo("2007300");
        assertThat(response.responseMessage()).isEqualTo("Successful");
        assertThat(response.accessToken()).isEqualTo("jwt-token");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresIn()).isEqualTo("900");
        verify(requestValidator).validateAccessTokenRequest(command, "application/json");
        verify(auditService).recordSignatureSuccess(command, 1L);
        verify(auditService).recordApi(eq(command), eq(1L), eq(200), eq("2007300"), eq("Successful"), any(Long.class));
    }

    @Test
    void successStillReturnsTokenWhenSignatureAuditFails() {
        TokenCommand command = command();
        ClientCredential credential = credential();
        IssuedAccessToken token = issuedToken();
        when(clientCredentialService.loadActiveClientCredential("client-id", "10.10.10.10"))
                .thenReturn(credential);
        when(signatureVerifier.verifyAuthSignature("client-id", "2026-04-30T10:00:00+07:00", "signature", credential))
                .thenReturn(true);
        doThrow(auditException("SIGNATURE_AUDIT_LOG_SAVE_FAILED"))
                .when(auditService).recordSignatureSuccess(command, 1L);
        when(jwtTokenService.issueAccessToken(credential)).thenReturn(token);

        AccessTokenB2BResponse response = service.issueB2BToken(command, "application/json");

        assertThat(response.responseCode()).isEqualTo("2007300");
        assertThat(response.accessToken()).isEqualTo("jwt-token");
        verify(auditService).recordApi(eq(command), eq(1L), eq(200), eq("2007300"), eq("Successful"), any(Long.class));
    }

    @Test
    void successStillReturnsTokenWhenApiAuditFails() {
        TokenCommand command = command();
        ClientCredential credential = credential();
        IssuedAccessToken token = issuedToken();
        when(clientCredentialService.loadActiveClientCredential("client-id", "10.10.10.10"))
                .thenReturn(credential);
        when(signatureVerifier.verifyAuthSignature("client-id", "2026-04-30T10:00:00+07:00", "signature", credential))
                .thenReturn(true);
        when(jwtTokenService.issueAccessToken(credential)).thenReturn(token);
        doThrow(auditException("API_AUDIT_LOG_SAVE_FAILED"))
                .when(auditService).recordApi(eq(command), eq(1L), eq(200), eq("2007300"), eq("Successful"), any(Long.class));

        AccessTokenB2BResponse response = service.issueB2BToken(command, "application/json");

        assertThat(response.responseCode()).isEqualTo("2007300");
        assertThat(response.accessToken()).isEqualTo("jwt-token");
    }

    @Test
    void invalidSignatureAuditsFailureAndThrowsUnauthorized() {
        TokenCommand command = command();
        ClientCredential credential = credential();
        when(clientCredentialService.loadActiveClientCredential("client-id", "10.10.10.10"))
                .thenReturn(credential);
        when(signatureVerifier.verifyAuthSignature("client-id", "2026-04-30T10:00:00+07:00", "signature", credential))
                .thenReturn(false);

        assertThatThrownBy(() -> service.issueB2BToken(command, "application/json"))
                .isInstanceOfSatisfying(SignatureVerificationException.class, exception -> {
                    assertThat(exception.getResponseCode()).isEqualTo("4017300");
                    assertThat(exception.getResponseMessage()).isEqualTo("Unauthorized");
                    assertThat(exception.getReason()).isEqualTo("INVALID_SIGNATURE");
                });

        verify(auditService).recordSignatureFailure(command, 1L, "INVALID_SIGNATURE");
        verify(auditService).recordApi(eq(command), eq(1L), eq(401), eq("4017300"), eq("Unauthorized"), any(Long.class));
        verify(jwtTokenService, never()).issueAccessToken(any());
    }

    @Test
    void invalidSignatureStillThrowsUnauthorizedWhenAuditFails() {
        TokenCommand command = command();
        ClientCredential credential = credential();
        when(clientCredentialService.loadActiveClientCredential("client-id", "10.10.10.10"))
                .thenReturn(credential);
        when(signatureVerifier.verifyAuthSignature("client-id", "2026-04-30T10:00:00+07:00", "signature", credential))
                .thenReturn(false);
        doThrow(auditException("SIGNATURE_AUDIT_LOG_SAVE_FAILED"))
                .when(auditService).recordSignatureFailure(command, 1L, "INVALID_SIGNATURE");
        doThrow(auditException("API_AUDIT_LOG_SAVE_FAILED"))
                .when(auditService).recordApi(eq(command), eq(1L), eq(401), eq("4017300"), eq("Unauthorized"), any(Long.class));

        assertThatThrownBy(() -> service.issueB2BToken(command, "application/json"))
                .isInstanceOfSatisfying(SignatureVerificationException.class, exception -> {
                    assertThat(exception.getResponseCode()).isEqualTo("4017300");
                    assertThat(exception.getReason()).isEqualTo("INVALID_SIGNATURE");
                });

        verify(jwtTokenService, never()).issueAccessToken(any());
    }

    @Test
    void validationFailureAuditsApiAndSkipsCredentialSignatureAndJwt() {
        TokenCommand command = command();
        SnapValidationException validationException = new SnapValidationException(
                "4007302",
                "Invalid Mandatory Field X-CLIENT-KEY",
                "Invalid mandatory field: X-CLIENT-KEY");
        doThrow(validationException).when(requestValidator).validateAccessTokenRequest(command, "application/json");

        assertThatThrownBy(() -> service.issueB2BToken(command, "application/json")).isSameAs(validationException);

        verify(auditService).recordApi(
                eq(command),
                eq(null),
                eq(400),
                eq("4007302"),
                eq("Invalid Mandatory Field X-CLIENT-KEY"),
                any(Long.class));
        verifyNoInteractions(clientCredentialService, signatureVerifier, jwtTokenService);
    }

    @Test
    void validationFailureStillThrowsValidationWhenApiAuditFails() {
        TokenCommand command = command();
        SnapValidationException validationException = new SnapValidationException(
                "4007302",
                "Invalid Mandatory Field X-CLIENT-KEY",
                "Invalid mandatory field: X-CLIENT-KEY");
        doThrow(validationException).when(requestValidator).validateAccessTokenRequest(command, "application/json");
        doThrow(auditException("API_AUDIT_LOG_SAVE_FAILED"))
                .when(auditService).recordApi(
                        eq(command),
                        eq(null),
                        eq(400),
                        eq("4007302"),
                        eq("Invalid Mandatory Field X-CLIENT-KEY"),
                        any(Long.class));

        assertThatThrownBy(() -> service.issueB2BToken(command, "application/json")).isSameAs(validationException);

        verifyNoInteractions(clientCredentialService, signatureVerifier, jwtTokenService);
    }

    @Test
    void tokenMetadataFailureAuditsGeneralError() {
        TokenCommand command = command();
        ClientCredential credential = credential();
        TokenMetadataPersistenceException persistenceException = new TokenMetadataPersistenceException(
                "General Error",
                "TOKEN_METADATA_SAVE_FAILED",
                new RuntimeException("db failure"));
        when(clientCredentialService.loadActiveClientCredential("client-id", "10.10.10.10"))
                .thenReturn(credential);
        when(signatureVerifier.verifyAuthSignature("client-id", "2026-04-30T10:00:00+07:00", "signature", credential))
                .thenReturn(true);
        when(jwtTokenService.issueAccessToken(credential)).thenThrow(persistenceException);

        assertThatThrownBy(() -> service.issueB2BToken(command, "application/json")).isSameAs(persistenceException);

        verify(auditService).recordSignatureSuccess(command, 1L);
        verify(auditService).recordApi(eq(command), eq(1L), eq(500), eq("5007300"), eq("General Error"), any(Long.class));
    }

    @Test
    void tokenMetadataFailureStillPropagatesWhenApiAuditFails() {
        TokenCommand command = command();
        ClientCredential credential = credential();
        TokenMetadataPersistenceException persistenceException = new TokenMetadataPersistenceException(
                "General Error",
                "TOKEN_METADATA_SAVE_FAILED",
                new RuntimeException("db failure"));
        when(clientCredentialService.loadActiveClientCredential("client-id", "10.10.10.10"))
                .thenReturn(credential);
        when(signatureVerifier.verifyAuthSignature("client-id", "2026-04-30T10:00:00+07:00", "signature", credential))
                .thenReturn(true);
        when(jwtTokenService.issueAccessToken(credential)).thenThrow(persistenceException);
        doThrow(auditException("API_AUDIT_LOG_SAVE_FAILED"))
                .when(auditService).recordApi(eq(command), eq(1L), eq(500), eq("5007300"), eq("General Error"), any(Long.class));

        assertThatThrownBy(() -> service.issueB2BToken(command, "application/json")).isSameAs(persistenceException);

        verify(auditService).recordSignatureSuccess(command, 1L);
    }

    @Test
    void dbUnavailableDuringCredentialLookupAuditsGeneralError() {
        TokenCommand command = command();
        DataAccessResourceFailureException databaseException =
                new DataAccessResourceFailureException("database unavailable");
        when(clientCredentialService.loadActiveClientCredential("client-id", "10.10.10.10"))
                .thenThrow(databaseException);

        assertThatThrownBy(() -> service.issueB2BToken(command, "application/json")).isSameAs(databaseException);

        verify(auditService).recordApi(
                eq(command),
                eq(null),
                eq(500),
                eq("5007300"),
                eq("General Error"),
                any(Long.class));
        verifyNoInteractions(signatureVerifier, jwtTokenService);
    }

    @Test
    void forbiddenScopeFailureAuditsForbiddenAndPropagates() {
        TokenCommand command = command();
        ClientCredential credential = credential();
        SnapForbiddenException forbiddenException = new SnapForbiddenException("Forbidden", "FORBIDDEN_SCOPE");
        when(clientCredentialService.loadActiveClientCredential("client-id", "10.10.10.10"))
                .thenReturn(credential);
        when(signatureVerifier.verifyAuthSignature("client-id", "2026-04-30T10:00:00+07:00", "signature", credential))
                .thenReturn(true);
        when(jwtTokenService.issueAccessToken(credential)).thenThrow(forbiddenException);

        assertThatThrownBy(() -> service.issueB2BToken(command, "application/json")).isSameAs(forbiddenException);

        verify(auditService).recordSignatureSuccess(command, 1L);
        verify(auditService).recordApi(eq(command), eq(1L), eq(403), eq("4037300"), eq("Forbidden"), any(Long.class));
    }

    private TokenCommand command() {
        return new TokenCommand(
                "client-id",
                "2026-04-30T10:00:00+07:00",
                "signature",
                "client_credentials",
                "10.10.10.10",
                "JUnit",
                "request-id");
    }

    private ClientCredential credential() {
        return new ClientCredential(
                1L,
                "client-id",
                "MERCHANT-001",
                "95221",
                900,
                "public-key-pem",
                "SHA256withRSA",
                "key-1",
                List.of("openid", "snap:auth:token"));
    }

    private IssuedAccessToken issuedToken() {
        return new IssuedAccessToken(
                "jwt-token",
                "Bearer",
                "900",
                "jti-1",
                Instant.parse("2026-04-30T03:00:00Z"),
                Instant.parse("2026-04-30T03:15:00Z"),
                List.of("openid", "snap:auth:token"));
    }

    private AuditPersistenceException auditException(String reason) {
        return new AuditPersistenceException("General Error", reason, new RuntimeException("db failure"));
    }

    @SuppressWarnings("unchecked")
    private SnapResponseCodeMapper responseCodeMapper() {
        ObjectProvider<ResponseCodeMappingJpaRepository> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        return new SnapResponseCodeMapper(provider);
    }
}
