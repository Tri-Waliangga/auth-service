package com.portfolio.authservice.application.signature;

import com.portfolio.authservice.application.audit.AuditService;
import com.portfolio.authservice.common.error.AuditPersistenceException;
import com.portfolio.authservice.common.error.SignatureVerificationException;
import com.portfolio.authservice.common.error.SnapGeneralException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.common.response.SnapResponseMapper;
import com.portfolio.authservice.domain.port.SignatureVerifier;
import com.portfolio.authservice.infrastructure.persistence.entity.ApiClientEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.ClientPublicKeyEntity;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiAuditLogJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiClientJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ClientPublicKeyJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.SignatureAuditLogJpaRepository;
import com.portfolio.authservice.interfaces.rest.dto.InternalSignatureVerifyRequest;
import com.portfolio.authservice.interfaces.rest.dto.InternalSignatureVerifyResponse;
import java.time.Clock;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
public class InternalSignatureVerificationService {

    private static final Logger log = LoggerFactory.getLogger(InternalSignatureVerificationService.class);
    private static final String SUCCESS_RESPONSE_CODE = SnapResponseMapper.SUCCESS_RESPONSE_CODE;
    private static final String UNAUTHORIZED_RESPONSE_CODE = SignatureVerificationException.UNAUTHORIZED_RESPONSE_CODE;
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private final ApiClientJpaRepository apiClientRepository;
    private final ClientPublicKeyJpaRepository publicKeyRepository;
    private final SignatureVerifier signatureVerifier;
    private final AuditService auditService;
    private final SnapResponseCodeMapper responseCodeMapper;
    private final Clock clock;

    public InternalSignatureVerificationService(
            ApiClientJpaRepository apiClientRepository,
            ClientPublicKeyJpaRepository publicKeyRepository,
            SignatureVerifier signatureVerifier,
            AuditService auditService,
            SnapResponseCodeMapper responseCodeMapper,
            Clock clock) {
        this.apiClientRepository = apiClientRepository;
        this.publicKeyRepository = publicKeyRepository;
        this.signatureVerifier = signatureVerifier;
        this.auditService = auditService;
        this.responseCodeMapper = responseCodeMapper;
        this.clock = clock;
    }

    @Transactional()
    public InternalSignatureVerifyResponse verify(
            InternalSignatureVerifyRequest request,
            String remoteIp,
            String userAgent,
            String requestId) {
        String stringToSign = resolveStringToSign(request);
        ApiClientEntity apiClient = null;

        try {
            apiClient = apiClientRepository.findActiveByClientId(request.clientId()).orElse(null);
            if (apiClient == null) {
                return invalid(null, request, requestId, stringToSign, "CLIENT_NOT_FOUND", remoteIp, userAgent);
            }

            ClientPublicKeyEntity publicKey = publicKeyRepository
                    .findActivePublicKeyByClient(apiClient.getId(), clock.instant())
                    .orElse(null);
            if (publicKey == null) {
                return invalid(apiClient.getId(), request, requestId, stringToSign, "PUBLIC_KEY_UNAVAILABLE", remoteIp, userAgent);
            }
            if (!SIGNATURE_ALGORITHM.equals(publicKey.getAlgorithm())) {
                return invalid(apiClient.getId(), request, requestId, stringToSign, "UNSUPPORTED_PUBLIC_KEY_ALGORITHM", remoteIp, userAgent);
            }

            boolean valid = signatureVerifier.verifySignature(
                    stringToSign,
                    request.signature(),
                    publicKey.getPublicKeyPem());
            if (!valid) {
                return invalid(apiClient.getId(), request, requestId, stringToSign, "INVALID_SIGNATURE", remoteIp, userAgent);
            }

            recordSuccess(apiClient.getId(), request, requestId, stringToSign, remoteIp, userAgent);
            return new InternalSignatureVerifyResponse(
                    true,
                    SUCCESS_RESPONSE_CODE,
                    responseCodeMapper.resolvePublicMessage(SUCCESS_RESPONSE_CODE),
                    null,
                    Map.of("algorithm", SIGNATURE_ALGORITHM, "keyId", publicKey.getKeyId()));
        } catch (SignatureVerificationException exception) {
            return invalid(
                    apiClient == null ? null : apiClient.getId(),
                    request,
                    requestId,
                    stringToSign,
                    exception.getReason(),
                    remoteIp,
                    userAgent);
        } catch (DataAccessException exception) {
            throw generalError(exception);
        }
    }

    private String resolveStringToSign(InternalSignatureVerifyRequest request) {
        if (StringUtils.hasText(request.stringToSign())) {
            return request.stringToSign();
        }
        return request.clientId() + "|" + request.timestamp();
    }

    private InternalSignatureVerifyResponse invalid(
            Long apiClientId,
            InternalSignatureVerifyRequest request,
            String requestId,
            String stringToSign,
            String failureReason,
            String remoteIp,
            String userAgent) {
        recordFailure(apiClientId, request, requestId, stringToSign, failureReason, remoteIp, userAgent);
        return new InternalSignatureVerifyResponse(
                false,
                UNAUTHORIZED_RESPONSE_CODE,
                responseCodeMapper.resolvePublicMessage(UNAUTHORIZED_RESPONSE_CODE),
                failureReason,
                Map.of());
    }

    private void recordSuccess(
            Long apiClientId,
            InternalSignatureVerifyRequest request,
            String requestId,
            String stringToSign,
            String remoteIp,
            String userAgent) {
        try {
            auditService.recordInternalSignatureSuccess(
                    apiClientId,
                    request.clientId(),
                    requestId,
                    stringToSign,
                    remoteIp,
                    userAgent);
        } catch (AuditPersistenceException exception) {
            logAuditFailure(requestId, request.clientId(), null, exception);
        }
    }

    private void recordFailure(
            Long apiClientId,
            InternalSignatureVerifyRequest request,
            String requestId,
            String stringToSign,
            String failureReason,
            String remoteIp,
            String userAgent) {
        try {
            auditService.recordInternalSignatureFailure(
                    apiClientId,
                    request.clientId(),
                    requestId,
                    stringToSign,
                    failureReason,
                    remoteIp,
                    userAgent);
        } catch (AuditPersistenceException exception) {
            logAuditFailure(requestId, request.clientId(), failureReason, exception);
        }
    }

    private SnapGeneralException generalError(DataAccessException exception) {
        return new SnapGeneralException(
                responseCodeMapper.resolvePublicMessage(SnapGeneralException.GENERAL_ERROR_RESPONSE_CODE),
                "INTERNAL_SIGNATURE_VERIFY_LOOKUP_FAILED",
                exception);
    }

    private void logAuditFailure(
            String requestId,
            String clientId,
            String failureReason,
            AuditPersistenceException exception) {
        log.warn(
                "audit_persistence_failed requestId={} auditType=INTERNAL_SIGNATURE clientId={} failureReason={} exceptionClass={} reason={}",
                safeValue(requestId),
                safeValue(clientId),
                safeValue(failureReason),
                exception.getClass().getName(),
                safeValue(exception.getReason()));
    }

    private String safeValue(String value) {
        if (value == null || value.isBlank()) {
            return "-";
        }
        return value.replaceAll("[^A-Za-z0-9_:\\-. ]", "_");
    }
}
