package com.portfolio.authservice.application.audit;

import com.portfolio.authservice.application.command.TokenCommand;
import com.portfolio.authservice.common.error.AuditPersistenceException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.infrastructure.persistence.entity.ApiAuditLogEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.ApiClientEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.SignatureAuditLogEntity;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiAuditLogJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiClientJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.SignatureAuditLogJpaRepository;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
@ConditionalOnBean({
        ApiAuditLogJpaRepository.class,
        ApiClientJpaRepository.class,
        SignatureAuditLogJpaRepository.class
})
public class AuditService {

    public static final String ACCESS_TOKEN_ENDPOINT = "/cashup/v1.0/access-token/b2b";

    private static final String AUTH_SIGNATURE_TYPE = "AUTH";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String SUCCESS = "SUCCESS";
    private static final String FAILED = "FAILED";

    private final SignatureAuditLogJpaRepository signatureAuditLogRepository;
    private final ApiAuditLogJpaRepository apiAuditLogRepository;
    private final ApiClientJpaRepository apiClientRepository;
    private final SnapResponseCodeMapper responseCodeMapper;

    public AuditService(
            SignatureAuditLogJpaRepository signatureAuditLogRepository,
            ApiAuditLogJpaRepository apiAuditLogRepository,
            ApiClientJpaRepository apiClientRepository,
            SnapResponseCodeMapper responseCodeMapper) {
        this.signatureAuditLogRepository = signatureAuditLogRepository;
        this.apiAuditLogRepository = apiAuditLogRepository;
        this.apiClientRepository = apiClientRepository;
        this.responseCodeMapper = responseCodeMapper;
    }

    public void recordSignatureSuccess(TokenCommand command, Long apiClientId) {
        recordSignature(command, apiClientId, SUCCESS, null);
    }

    public void recordSignatureFailure(TokenCommand command, Long apiClientId, String failureReason) {
        recordSignature(command, apiClientId, FAILED, failureReason);
    }

    public void recordApi(
            TokenCommand command,
            Long apiClientId,
            int httpStatus,
            String responseCode,
            String responseMessage,
            long latencyMs) {
        try {
            ApiAuditLogEntity auditLog = new ApiAuditLogEntity();
            auditLog.setApiClient(reference(apiClientId));
            auditLog.setRequestId(command.requestId());
            auditLog.setEndpointPath(ACCESS_TOKEN_ENDPOINT);
            auditLog.setHttpMethod("POST");
            auditLog.setHttpStatus(httpStatus);
            auditLog.setResponseCode(responseCode);
            auditLog.setResponseMessage(responseMessage);
            auditLog.setLatencyMs(latencyMs);
            auditLog.setRemoteIp(command.remoteIp());
            apiAuditLogRepository.save(auditLog);
        } catch (DataAccessException exception) {
            throw generalError("API_AUDIT_LOG_SAVE_FAILED", exception);
        } catch (RuntimeException exception) {
            throw generalError("API_AUDIT_LOG_SAVE_FAILED", exception);
        }
    }

    private void recordSignature(
            TokenCommand command,
            Long apiClientId,
            String validationResult,
            String failureReason) {
        try {
            SignatureAuditLogEntity auditLog = new SignatureAuditLogEntity();
            auditLog.setApiClient(reference(apiClientId));
            auditLog.setRequestId(command.requestId());
            auditLog.setSignatureType(AUTH_SIGNATURE_TYPE);
            auditLog.setAlgorithm(SIGNATURE_ALGORITHM);
            auditLog.setStringToSignHash(sha256Hex(command.clientId() + "|" + command.timestamp()));
            auditLog.setValidationResult(validationResult);
            auditLog.setFailureReason(failureReason);
            auditLog.setRemoteIp(command.remoteIp());
            auditLog.setUserAgent(command.userAgent());
            signatureAuditLogRepository.save(auditLog);
        } catch (DataAccessException exception) {
            throw generalError("SIGNATURE_AUDIT_LOG_SAVE_FAILED", exception);
        } catch (RuntimeException exception) {
            throw generalError("SIGNATURE_AUDIT_LOG_SAVE_FAILED", exception);
        }
    }

    private ApiClientEntity reference(Long apiClientId) {
        if (apiClientId == null) {
            return null;
        }
        return apiClientRepository.getReferenceById(apiClientId);
    }

    private String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("SHA-256 digest is unavailable", exception);
        }
    }

    private AuditPersistenceException generalError(String reason, RuntimeException cause) {
        return new AuditPersistenceException(
                responseCodeMapper.resolvePublicMessage(AuditPersistenceException.GENERAL_ERROR_RESPONSE_CODE),
                reason,
                cause);
    }
}
