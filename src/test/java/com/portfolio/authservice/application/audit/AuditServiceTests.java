package com.portfolio.authservice.application.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.portfolio.authservice.application.command.TokenCommand;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.infrastructure.persistence.entity.ApiAuditLogEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.ApiClientEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.SignatureAuditLogEntity;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiAuditLogJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiClientJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.SignatureAuditLogJpaRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;

class AuditServiceTests {

    private SignatureAuditLogJpaRepository signatureAuditLogRepository;
    private ApiAuditLogJpaRepository apiAuditLogRepository;
    private ApiClientJpaRepository apiClientRepository;
    private ApiClientEntity apiClient;
    private AuditService service;

    @BeforeEach
    void setUp() {
        signatureAuditLogRepository = mock(SignatureAuditLogJpaRepository.class);
        apiAuditLogRepository = mock(ApiAuditLogJpaRepository.class);
        apiClientRepository = mock(ApiClientJpaRepository.class);
        apiClient = new ApiClientEntity();
        ReflectionTestUtils.setField(apiClient, "id", 1L);
        when(apiClientRepository.getReferenceById(1L)).thenReturn(apiClient);
        when(signatureAuditLogRepository.save(any(SignatureAuditLogEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(apiAuditLogRepository.save(any(ApiAuditLogEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        service = new AuditService(
                signatureAuditLogRepository,
                apiAuditLogRepository,
                apiClientRepository,
                responseCodeMapper());
    }

    @Test
    void recordsSignatureAuditWithHashedStringToSign() throws Exception {
        TokenCommand command = command();

        service.recordSignatureFailure(command, 1L, "INVALID_SIGNATURE");

        ArgumentCaptor<SignatureAuditLogEntity> captor = ArgumentCaptor.forClass(SignatureAuditLogEntity.class);
        verify(signatureAuditLogRepository).save(captor.capture());
        SignatureAuditLogEntity auditLog = captor.getValue();
        assertThat(auditLog.getApiClient()).isSameAs(apiClient);
        assertThat(auditLog.getRequestId()).isEqualTo("request-id");
        assertThat(auditLog.getSignatureType()).isEqualTo("AUTH");
        assertThat(auditLog.getAlgorithm()).isEqualTo("SHA256withRSA");
        assertThat(auditLog.getStringToSignHash()).isEqualTo(sha256Hex("client-id|2026-04-30T10:00:00+07:00"));
        assertThat(auditLog.getStringToSignHash()).doesNotContain("client-id|");
        assertThat(auditLog.getValidationResult()).isEqualTo("FAILED");
        assertThat(auditLog.getFailureReason()).isEqualTo("INVALID_SIGNATURE");
        assertThat(auditLog.getRemoteIp()).isEqualTo("10.10.10.10");
        assertThat(auditLog.getUserAgent()).isEqualTo("JUnit");
    }

    @Test
    void recordsApiAudit() {
        TokenCommand command = command();

        service.recordApi(command, 1L, 200, "2007300", "Successful", 12L);

        ArgumentCaptor<ApiAuditLogEntity> captor = ArgumentCaptor.forClass(ApiAuditLogEntity.class);
        verify(apiAuditLogRepository).save(captor.capture());
        ApiAuditLogEntity auditLog = captor.getValue();
        assertThat(auditLog.getApiClient()).isSameAs(apiClient);
        assertThat(auditLog.getRequestId()).isEqualTo("request-id");
        assertThat(auditLog.getEndpointPath()).isEqualTo("/cashup/v1.0/access-token/b2b");
        assertThat(auditLog.getHttpMethod()).isEqualTo("POST");
        assertThat(auditLog.getHttpStatus()).isEqualTo(200);
        assertThat(auditLog.getResponseCode()).isEqualTo("2007300");
        assertThat(auditLog.getResponseMessage()).isEqualTo("Successful");
        assertThat(auditLog.getLatencyMs()).isEqualTo(12L);
        assertThat(auditLog.getRemoteIp()).isEqualTo("10.10.10.10");
    }

    private TokenCommand command() {
        return new TokenCommand(
                "client-id",
                "2026-04-30T10:00:00+07:00",
                "raw-signature",
                "client_credentials",
                "10.10.10.10",
                "JUnit",
                "request-id");
    }

    private String sha256Hex(String value) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
    }

    @SuppressWarnings("unchecked")
    private SnapResponseCodeMapper responseCodeMapper() {
        ObjectProvider<ResponseCodeMappingJpaRepository> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        return new SnapResponseCodeMapper(provider);
    }
}
