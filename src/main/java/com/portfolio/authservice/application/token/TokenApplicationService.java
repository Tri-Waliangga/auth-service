package com.portfolio.authservice.application.token;

import com.portfolio.authservice.application.audit.AuditService;
import com.portfolio.authservice.application.command.TokenCommand;
import com.portfolio.authservice.application.credential.ClientCredential;
import com.portfolio.authservice.application.credential.ClientCredentialService;
import com.portfolio.authservice.application.validation.SnapRequestValidator;
import com.portfolio.authservice.common.error.AuditPersistenceException;
import com.portfolio.authservice.common.error.SignatureVerificationException;
import com.portfolio.authservice.common.error.SnapException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.common.response.SnapResponseMapper;
import com.portfolio.authservice.domain.port.SignatureVerifier;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiAuditLogJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiClientJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ClientPublicKeyJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ClientScopeJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.OauthAccessTokenJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.SignatureAuditLogJpaRepository;
import com.portfolio.authservice.interfaces.rest.dto.AccessTokenB2BResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.stereotype.Service;

@Service
@ConditionalOnBean({
        ApiAuditLogJpaRepository.class,
        ApiClientJpaRepository.class,
        ClientPublicKeyJpaRepository.class,
        ClientScopeJpaRepository.class,
        OauthAccessTokenJpaRepository.class,
        SignatureAuditLogJpaRepository.class
})
public class TokenApplicationService {

    private static final Logger log = LoggerFactory.getLogger(TokenApplicationService.class);
    private static final String GENERAL_ERROR_RESPONSE_CODE = "5007300";

    private final SnapRequestValidator requestValidator;
    private final ClientCredentialService clientCredentialService;
    private final SignatureVerifier signatureVerifier;
    private final JwtTokenService jwtTokenService;
    private final AuditService auditService;
    private final SnapResponseCodeMapper responseCodeMapper;
    private final SnapResponseMapper responseMapper;

    public TokenApplicationService(
            SnapRequestValidator requestValidator,
            ClientCredentialService clientCredentialService,
            SignatureVerifier signatureVerifier,
            JwtTokenService jwtTokenService,
            AuditService auditService,
            SnapResponseCodeMapper responseCodeMapper,
            SnapResponseMapper responseMapper) {
        this.requestValidator = requestValidator;
        this.clientCredentialService = clientCredentialService;
        this.signatureVerifier = signatureVerifier;
        this.jwtTokenService = jwtTokenService;
        this.auditService = auditService;
        this.responseCodeMapper = responseCodeMapper;
        this.responseMapper = responseMapper;
    }

    public AccessTokenB2BResponse issueB2BToken(TokenCommand command, String contentType) {
        long startedAtNanos = System.nanoTime();
        Long apiClientId = null;

        try {
            requestValidator.validateAccessTokenRequest(command, contentType);

            ClientCredential credential = clientCredentialService.loadActiveClientCredential(
                    command.clientId(),
                    command.remoteIp());
            apiClientId = credential.apiClientId();

            boolean signatureValid = verifySignature(command, credential, apiClientId);
            if (!signatureValid) {
                recordSignatureFailure(command, apiClientId, "INVALID_SIGNATURE");
                throw unauthorized("INVALID_SIGNATURE");
            }
            recordSignatureSuccess(command, apiClientId);

            IssuedAccessToken issuedToken = jwtTokenService.issueAccessToken(credential);
            AccessTokenB2BResponse response = responseMapper.accessTokenSuccess(issuedToken);
            recordApi(
                    command,
                    apiClientId,
                    200,
                    response.responseCode(),
                    response.responseMessage(),
                    latencyMs(startedAtNanos));
            return response;
        } catch (SnapException exception) {
            auditFailure(command, apiClientId, exception.getResponseCode(), exception.getResponseMessage(), startedAtNanos);
            throw exception;
        } catch (RuntimeException exception) {
            auditFailure(
                    command,
                    apiClientId,
                    GENERAL_ERROR_RESPONSE_CODE,
                    responseCodeMapper.resolvePublicMessage(GENERAL_ERROR_RESPONSE_CODE),
                    startedAtNanos);
            throw exception;
        }
    }

    private boolean verifySignature(TokenCommand command, ClientCredential credential, Long apiClientId) {
        try {
            return signatureVerifier.verifyAuthSignature(
                    command.clientId(),
                    command.timestamp(),
                    command.signature(),
                    credential);
        } catch (SignatureVerificationException exception) {
            recordSignatureFailure(command, apiClientId, exception.getReason());
            throw exception;
        }
    }

    private SignatureVerificationException unauthorized(String reason) {
        return new SignatureVerificationException(
                responseCodeMapper.resolvePublicMessage(SignatureVerificationException.UNAUTHORIZED_RESPONSE_CODE),
                reason);
    }

    private void auditFailure(
            TokenCommand command,
            Long apiClientId,
            String responseCode,
            String responseMessage,
            long startedAtNanos) {
        recordApi(
                command,
                apiClientId,
                responseMapper.httpStatus(responseCode).value(),
                responseCode,
                responseMessage,
                latencyMs(startedAtNanos));
    }

    private void recordSignatureSuccess(TokenCommand command, Long apiClientId) {
        try {
            auditService.recordSignatureSuccess(command, apiClientId);
        } catch (AuditPersistenceException exception) {
            logAuditFailure(command, "SIGNATURE", null, exception);
        }
    }

    private void recordSignatureFailure(TokenCommand command, Long apiClientId, String failureReason) {
        try {
            auditService.recordSignatureFailure(command, apiClientId, failureReason);
        } catch (AuditPersistenceException exception) {
            logAuditFailure(command, "SIGNATURE", null, exception);
        }
    }

    private void recordApi(
            TokenCommand command,
            Long apiClientId,
            int httpStatus,
            String responseCode,
            String responseMessage,
            long latencyMs) {
        try {
            auditService.recordApi(command, apiClientId, httpStatus, responseCode, responseMessage, latencyMs);
        } catch (AuditPersistenceException exception) {
            logAuditFailure(command, "API", responseCode, exception);
        }
    }

    private void logAuditFailure(
            TokenCommand command,
            String auditType,
            String responseCode,
            AuditPersistenceException exception) {
        log.warn(
                "audit_persistence_failed requestId={} auditType={} responseCode={} exceptionClass={} reason={}",
                safeValue(command.requestId()),
                auditType,
                safeValue(responseCode),
                exception.getClass().getName(),
                safeValue(exception.getReason()));
    }

    private String safeValue(String value) {
        if (value == null || value.isBlank()) {
            return "-";
        }
        return value.replaceAll("[^A-Za-z0-9_:\\-. ]", "_");
    }

    private long latencyMs(long startedAtNanos) {
        return Math.max(0L, (System.nanoTime() - startedAtNanos) / 1_000_000L);
    }
}
