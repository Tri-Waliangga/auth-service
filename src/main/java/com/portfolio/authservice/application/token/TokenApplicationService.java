package com.portfolio.authservice.application.token;

import com.portfolio.authservice.application.audit.AuditService;
import com.portfolio.authservice.application.command.TokenCommand;
import com.portfolio.authservice.application.credential.ClientCredential;
import com.portfolio.authservice.application.credential.ClientCredentialException;
import com.portfolio.authservice.application.credential.ClientCredentialService;
import com.portfolio.authservice.application.validation.SnapRequestValidator;
import com.portfolio.authservice.common.error.SignatureVerificationException;
import com.portfolio.authservice.common.error.SnapValidationException;
import com.portfolio.authservice.common.error.TokenMetadataPersistenceException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.domain.port.SignatureVerifier;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiAuditLogJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiClientJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ClientPublicKeyJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ClientScopeJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.OauthAccessTokenJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.SignatureAuditLogJpaRepository;
import com.portfolio.authservice.interfaces.rest.dto.AccessTokenB2BResponse;
import java.util.Map;
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

    public static final String SUCCESS_RESPONSE_CODE = "2007300";
    private static final String GENERAL_ERROR_RESPONSE_CODE = "5007300";

    private final SnapRequestValidator requestValidator;
    private final ClientCredentialService clientCredentialService;
    private final SignatureVerifier signatureVerifier;
    private final JwtTokenService jwtTokenService;
    private final AuditService auditService;
    private final SnapResponseCodeMapper responseCodeMapper;

    public TokenApplicationService(
            SnapRequestValidator requestValidator,
            ClientCredentialService clientCredentialService,
            SignatureVerifier signatureVerifier,
            JwtTokenService jwtTokenService,
            AuditService auditService,
            SnapResponseCodeMapper responseCodeMapper) {
        this.requestValidator = requestValidator;
        this.clientCredentialService = clientCredentialService;
        this.signatureVerifier = signatureVerifier;
        this.jwtTokenService = jwtTokenService;
        this.auditService = auditService;
        this.responseCodeMapper = responseCodeMapper;
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
                auditService.recordSignatureFailure(command, apiClientId, "INVALID_SIGNATURE");
                throw unauthorized("INVALID_SIGNATURE");
            }
            auditService.recordSignatureSuccess(command, apiClientId);

            IssuedAccessToken issuedToken = jwtTokenService.issueAccessToken(credential);
            AccessTokenB2BResponse response = new AccessTokenB2BResponse(
                    SUCCESS_RESPONSE_CODE,
                    responseCodeMapper.resolveMessage(SUCCESS_RESPONSE_CODE),
                    issuedToken.accessToken(),
                    issuedToken.tokenType(),
                    issuedToken.expiresIn(),
                    Map.of());
            auditService.recordApi(
                    command,
                    apiClientId,
                    200,
                    response.responseCode(),
                    response.responseMessage(),
                    latencyMs(startedAtNanos));
            return response;
        } catch (SnapValidationException exception) {
            auditFailure(command, apiClientId, exception.getResponseCode(), exception.getResponseMessage(), startedAtNanos);
            throw exception;
        } catch (ClientCredentialException exception) {
            auditFailure(command, apiClientId, exception.getResponseCode(), exception.getResponseMessage(), startedAtNanos);
            throw exception;
        } catch (SignatureVerificationException exception) {
            auditFailure(command, apiClientId, exception.getResponseCode(), exception.getResponseMessage(), startedAtNanos);
            throw exception;
        } catch (TokenMetadataPersistenceException exception) {
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
            auditService.recordSignatureFailure(command, apiClientId, exception.getReason());
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
        auditService.recordApi(
                command,
                apiClientId,
                httpStatus(responseCode),
                responseCode,
                responseMessage,
                latencyMs(startedAtNanos));
    }

    private int httpStatus(String responseCode) {
        try {
            return Integer.parseInt(responseCode.substring(0, 3));
        } catch (RuntimeException exception) {
            return 500;
        }
    }

    private long latencyMs(long startedAtNanos) {
        return Math.max(0L, (System.nanoTime() - startedAtNanos) / 1_000_000L);
    }
}
