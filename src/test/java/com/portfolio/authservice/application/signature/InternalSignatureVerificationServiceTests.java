package com.portfolio.authservice.application.signature;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.portfolio.authservice.application.audit.AuditService;
import com.portfolio.authservice.common.error.AuditPersistenceException;
import com.portfolio.authservice.common.error.SignatureVerificationException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.domain.port.SignatureVerifier;
import com.portfolio.authservice.infrastructure.persistence.entity.ApiClientEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.ClientPublicKeyEntity;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiClientJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ClientPublicKeyJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import com.portfolio.authservice.interfaces.rest.dto.InternalSignatureVerifyRequest;
import com.portfolio.authservice.interfaces.rest.dto.InternalSignatureVerifyResponse;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;

class InternalSignatureVerificationServiceTests {

    private static final Instant NOW = Instant.parse("2026-05-07T08:00:00Z");

    private ApiClientJpaRepository apiClientRepository;
    private ClientPublicKeyJpaRepository publicKeyRepository;
    private SignatureVerifier signatureVerifier;
    private AuditService auditService;
    private InternalSignatureVerificationService service;
    private ApiClientEntity apiClient;
    private ClientPublicKeyEntity publicKey;

    @BeforeEach
    void setUp() {
        apiClientRepository = mock(ApiClientJpaRepository.class);
        publicKeyRepository = mock(ClientPublicKeyJpaRepository.class);
        signatureVerifier = mock(SignatureVerifier.class);
        auditService = mock(AuditService.class);
        apiClient = new ApiClientEntity();
        apiClient.setClientId("client-id");
        ReflectionTestUtils.setField(apiClient, "id", 1L);
        publicKey = new ClientPublicKeyEntity();
        publicKey.setPublicKeyPem("public-key-pem");
        publicKey.setAlgorithm("SHA256withRSA");
        publicKey.setKeyId("key-1");

        service = new InternalSignatureVerificationService(
                apiClientRepository,
                publicKeyRepository,
                signatureVerifier,
                auditService,
                responseCodeMapper(),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void validSignatureReturnsSuccessAndAudits() {
        when(apiClientRepository.findActiveByClientId("client-id")).thenReturn(Optional.of(apiClient));
        when(publicKeyRepository.findActivePublicKeyByClient(1L, NOW)).thenReturn(Optional.of(publicKey));
        when(signatureVerifier.verifySignature("client-id|2026-05-07T15:00:00+07:00", "signature", "public-key-pem"))
                .thenReturn(true);

        InternalSignatureVerifyResponse response = service.verify(
                request(null),
                "10.10.10.10",
                "JUnit",
                "request-id");

        assertThat(response.valid()).isTrue();
        assertThat(response.responseCode()).isEqualTo("2007300");
        assertThat(response.responseMessage()).isEqualTo("Successful");
        assertThat(response.failureReason()).isNull();
        assertThat(response.additionalInfo()).containsEntry("keyId", "key-1");
        verify(auditService).recordInternalSignatureSuccess(
                1L,
                "client-id",
                "request-id",
                "client-id|2026-05-07T15:00:00+07:00",
                "10.10.10.10",
                "JUnit");
    }

    @Test
    void invalidSignatureReturnsInvalidAndAuditsFailure() {
        when(apiClientRepository.findActiveByClientId("client-id")).thenReturn(Optional.of(apiClient));
        when(publicKeyRepository.findActivePublicKeyByClient(1L, NOW)).thenReturn(Optional.of(publicKey));
        when(signatureVerifier.verifySignature("client-id|2026-05-07T15:00:00+07:00", "signature", "public-key-pem"))
                .thenReturn(false);

        InternalSignatureVerifyResponse response = service.verify(
                request(null),
                "10.10.10.10",
                "JUnit",
                "request-id");

        assertThat(response.valid()).isFalse();
        assertThat(response.responseCode()).isEqualTo("4017300");
        assertThat(response.responseMessage()).isEqualTo("Unauthorized");
        assertThat(response.failureReason()).isEqualTo("INVALID_SIGNATURE");
        verify(auditService).recordInternalSignatureFailure(
                1L,
                "client-id",
                "request-id",
                "client-id|2026-05-07T15:00:00+07:00",
                "INVALID_SIGNATURE",
                "10.10.10.10",
                "JUnit");
    }

    @Test
    void unknownClientReturnsInvalidWithoutVerifyingSignature() {
        when(apiClientRepository.findActiveByClientId("client-id")).thenReturn(Optional.empty());

        InternalSignatureVerifyResponse response = service.verify(
                request(null),
                "10.10.10.10",
                "JUnit",
                "request-id");

        assertThat(response.valid()).isFalse();
        assertThat(response.failureReason()).isEqualTo("CLIENT_NOT_FOUND");
        verify(signatureVerifier, never()).verifySignature(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString());
        verify(auditService).recordInternalSignatureFailure(
                null,
                "client-id",
                "request-id",
                "client-id|2026-05-07T15:00:00+07:00",
                "CLIENT_NOT_FOUND",
                "10.10.10.10",
                "JUnit");
    }

    @Test
    void missingActivePublicKeyReturnsInvalid() {
        when(apiClientRepository.findActiveByClientId("client-id")).thenReturn(Optional.of(apiClient));
        when(publicKeyRepository.findActivePublicKeyByClient(1L, NOW)).thenReturn(Optional.empty());

        InternalSignatureVerifyResponse response = service.verify(request(null), "10.10.10.10", "JUnit", "request-id");

        assertThat(response.valid()).isFalse();
        assertThat(response.failureReason()).isEqualTo("PUBLIC_KEY_UNAVAILABLE");
        verify(signatureVerifier, never()).verifySignature(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void unsupportedPublicKeyAlgorithmReturnsInvalid() {
        publicKey.setAlgorithm("RS256");
        when(apiClientRepository.findActiveByClientId("client-id")).thenReturn(Optional.of(apiClient));
        when(publicKeyRepository.findActivePublicKeyByClient(1L, NOW)).thenReturn(Optional.of(publicKey));

        InternalSignatureVerifyResponse response = service.verify(request(null), "10.10.10.10", "JUnit", "request-id");

        assertThat(response.valid()).isFalse();
        assertThat(response.failureReason()).isEqualTo("UNSUPPORTED_PUBLIC_KEY_ALGORITHM");
        verify(signatureVerifier, never()).verifySignature(
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void stringToSignOverrideIsVerifiedDirectly() {
        when(apiClientRepository.findActiveByClientId("client-id")).thenReturn(Optional.of(apiClient));
        when(publicKeyRepository.findActivePublicKeyByClient(1L, NOW)).thenReturn(Optional.of(publicKey));
        when(signatureVerifier.verifySignature("custom-string-to-sign", "signature", "public-key-pem"))
                .thenReturn(true);

        InternalSignatureVerifyResponse response = service.verify(
                request("custom-string-to-sign"),
                "10.10.10.10",
                "JUnit",
                "request-id");

        assertThat(response.valid()).isTrue();
        verify(auditService).recordInternalSignatureSuccess(
                1L,
                "client-id",
                "request-id",
                "custom-string-to-sign",
                "10.10.10.10",
                "JUnit");
    }

    @Test
    void signatureVerifierExceptionReturnsInvalidReason() {
        when(apiClientRepository.findActiveByClientId("client-id")).thenReturn(Optional.of(apiClient));
        when(publicKeyRepository.findActivePublicKeyByClient(1L, NOW)).thenReturn(Optional.of(publicKey));
        when(signatureVerifier.verifySignature("client-id|2026-05-07T15:00:00+07:00", "signature", "public-key-pem"))
                .thenThrow(new SignatureVerificationException("Unauthorized", "INVALID_SIGNATURE_FORMAT"));

        InternalSignatureVerifyResponse response = service.verify(request(null), "10.10.10.10", "JUnit", "request-id");

        assertThat(response.valid()).isFalse();
        assertThat(response.failureReason()).isEqualTo("INVALID_SIGNATURE_FORMAT");
    }

    @Test
    void auditPersistenceFailureDoesNotChangeVerificationResult() {
        when(apiClientRepository.findActiveByClientId("client-id")).thenReturn(Optional.of(apiClient));
        when(publicKeyRepository.findActivePublicKeyByClient(1L, NOW)).thenReturn(Optional.of(publicKey));
        when(signatureVerifier.verifySignature("client-id|2026-05-07T15:00:00+07:00", "signature", "public-key-pem"))
                .thenReturn(true);
        doThrow(new AuditPersistenceException("General Error", "SIGNATURE_AUDIT_LOG_SAVE_FAILED", new RuntimeException()))
                .when(auditService)
                .recordInternalSignatureSuccess(
                        eq(1L),
                        eq("client-id"),
                        eq("request-id"),
                        eq("client-id|2026-05-07T15:00:00+07:00"),
                        eq("10.10.10.10"),
                        eq("JUnit"));

        InternalSignatureVerifyResponse response = service.verify(request(null), "10.10.10.10", "JUnit", "request-id");

        assertThat(response.valid()).isTrue();
        assertThat(response.responseCode()).isEqualTo("2007300");
    }

    private InternalSignatureVerifyRequest request(String stringToSign) {
        return new InternalSignatureVerifyRequest(
                "client-id",
                "2026-05-07T15:00:00+07:00",
                "signature",
                stringToSign);
    }

    @SuppressWarnings("unchecked")
    private SnapResponseCodeMapper responseCodeMapper() {
        ObjectProvider<ResponseCodeMappingJpaRepository> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        return new SnapResponseCodeMapper(provider);
    }
}
