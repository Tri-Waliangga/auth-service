package com.portfolio.authservice.application.token;

import com.portfolio.authservice.application.audit.AuditService;
import com.portfolio.authservice.application.command.TokenCommand;
import com.portfolio.authservice.application.credential.ClientCredential;
import com.portfolio.authservice.application.credential.ClientCredentialService;
import com.portfolio.authservice.application.observability.TokenMetrics;
import com.portfolio.authservice.application.validation.SnapRequestValidator;
import com.portfolio.authservice.common.error.AuditPersistenceException;
import com.portfolio.authservice.common.error.SignatureVerificationException;
import com.portfolio.authservice.common.error.SnapException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.common.response.SnapResponseMapper;
import com.portfolio.authservice.domain.port.SignatureVerifier;
import com.portfolio.authservice.interfaces.rest.dto.AccessTokenB2BResponse;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
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
    private final TokenMetrics tokenMetrics;

    public TokenApplicationService(
            SnapRequestValidator requestValidator,
            ClientCredentialService clientCredentialService,
            SignatureVerifier signatureVerifier,
            JwtTokenService jwtTokenService,
            AuditService auditService,
            SnapResponseCodeMapper responseCodeMapper,
            SnapResponseMapper responseMapper,
            TokenMetrics tokenMetrics) {
        this.requestValidator = requestValidator;
        this.clientCredentialService = clientCredentialService;
        this.signatureVerifier = signatureVerifier;
        this.jwtTokenService = jwtTokenService;
        this.auditService = auditService;
        this.responseCodeMapper = responseCodeMapper;
        this.responseMapper = responseMapper;
        this.tokenMetrics = tokenMetrics;
    }

    public AccessTokenB2BResponse issueB2BToken(TokenCommand command, String contentType) {
        long startedAtNanos = System.nanoTime();
        Timer.Sample latencySample = tokenMetrics.startLatencyTimer();
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
            tokenMetrics.recordSuccess();
            return response;
        } catch (SnapException exception) {
            recordFailureMetrics(exception);
            auditFailure(command, apiClientId, exception.getResponseCode(), exception.getResponseMessage(), startedAtNanos);
            throw exception;
        } catch (RuntimeException exception) {
            tokenMetrics.recordFailure();
            auditFailure(
                    command,
                    apiClientId,
                    GENERAL_ERROR_RESPONSE_CODE,
                    responseCodeMapper.resolvePublicMessage(GENERAL_ERROR_RESPONSE_CODE),
                    startedAtNanos);
            throw exception;
        } finally {
            tokenMetrics.recordLatency(latencySample);
        }
    }

    private void recordFailureMetrics(SnapException exception) {
        tokenMetrics.recordFailure();
        if (exception instanceof SignatureVerificationException) {
            tokenMetrics.recordInvalidSignature();
        }
        if (isUnauthorized(exception.getResponseCode())) {
            tokenMetrics.recordUnauthorized();
        }
    }

    private boolean isUnauthorized(String responseCode) {
        return responseCode != null && responseCode.startsWith("401");
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
