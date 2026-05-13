package com.portfolio.authservice.application.token;

import com.portfolio.authservice.application.credential.ClientCredential;
import com.portfolio.authservice.common.error.TokenMetadataPersistenceException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.infrastructure.persistence.entity.ApiClientEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.OauthAccessTokenEntity;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiClientJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.OauthAccessTokenJpaRepository;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.HexFormat;
import java.util.Optional;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
public class TokenMetadataService {

    private static final String TOKEN_TYPE = "Bearer";
    private static final String SAVE_FAILED_REASON = "TOKEN_METADATA_SAVE_FAILED";
    private static final String LOOKUP_FAILED_REASON = "TOKEN_METADATA_LOOKUP_FAILED";

    private final OauthAccessTokenJpaRepository accessTokenRepository;
    private final ApiClientJpaRepository apiClientRepository;
    private final SnapResponseCodeMapper responseCodeMapper;
    private final Clock clock;

    public TokenMetadataService(
            OauthAccessTokenJpaRepository accessTokenRepository,
            ApiClientJpaRepository apiClientRepository,
            SnapResponseCodeMapper responseCodeMapper,
            Clock clock) {
        this.accessTokenRepository = accessTokenRepository;
        this.apiClientRepository = apiClientRepository;
        this.responseCodeMapper = responseCodeMapper;
        this.clock = clock;
    }

    @Transactional
    public void saveIssuedToken(ClientCredential credential, IssuedAccessToken issuedToken) {
        validateSaveCommand(credential, issuedToken);
        try {
            ApiClientEntity apiClient = apiClientRepository.getReferenceById(credential.apiClientId());

            OauthAccessTokenEntity tokenMetadata = new OauthAccessTokenEntity();
            tokenMetadata.setApiClient(apiClient);
            tokenMetadata.setTokenJti(issuedToken.jti());
            tokenMetadata.setTokenHash(sha256Hex(issuedToken.accessToken()));
            tokenMetadata.setTokenType(TOKEN_TYPE);
            tokenMetadata.setScopes(String.join(" ", issuedToken.scopes()));
            tokenMetadata.setIssuedAt(issuedToken.issuedAt());
            tokenMetadata.setExpiresAt(issuedToken.expiresAt());
            accessTokenRepository.save(tokenMetadata);
        } catch (DataAccessException exception) {
            throw generalError(SAVE_FAILED_REASON, exception);
        } catch (RuntimeException exception) {
            throw generalError(SAVE_FAILED_REASON, exception);
        }
    }

    @Transactional(readOnly = true)
    public Optional<OauthAccessTokenEntity> findActiveByRawToken(String rawToken) {
        if (!StringUtils.hasText(rawToken)) {
            return Optional.empty();
        }

        try {
            return accessTokenRepository.findActiveByTokenHash(sha256Hex(rawToken), clock.instant());
        } catch (DataAccessException exception) {
            throw generalError(LOOKUP_FAILED_REASON, exception);
        } catch (RuntimeException exception) {
            throw generalError(LOOKUP_FAILED_REASON, exception);
        }
    }

    private void validateSaveCommand(ClientCredential credential, IssuedAccessToken issuedToken) {
        if (credential == null
                || credential.apiClientId() == null
                || issuedToken == null
                || !StringUtils.hasText(issuedToken.accessToken())
                || !StringUtils.hasText(issuedToken.jti())
                || issuedToken.scopes() == null
                || issuedToken.issuedAt() == null
                || issuedToken.expiresAt() == null) {
            throw new IllegalArgumentException("Token metadata command is incomplete");
        }
    }

    private String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("SHA-256 digest is unavailable", exception);
        }
    }

    private TokenMetadataPersistenceException generalError(String reason, RuntimeException cause) {
        return new TokenMetadataPersistenceException(
                responseCodeMapper.resolvePublicMessage(TokenMetadataPersistenceException.GENERAL_ERROR_RESPONSE_CODE),
                reason,
                cause);
    }
}
