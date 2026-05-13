package com.portfolio.authservice.application.token;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.portfolio.authservice.common.error.SnapUnauthorizedException;
import com.portfolio.authservice.common.error.TokenMetadataPersistenceException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.config.JwtProperties;
import com.portfolio.authservice.infrastructure.persistence.entity.OauthAccessTokenEntity;
import com.portfolio.authservice.infrastructure.persistence.repository.OauthAccessTokenJpaRepository;
import com.portfolio.authservice.interfaces.rest.dto.TokenIntrospectionResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
public class TokenIntrospectionService {

    private static final String RSA_KEY_FACTORY = "RSA";
    private static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
    private static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
    private static final String LOOKUP_FAILED_REASON = "TOKEN_INTROSPECTION_LOOKUP_FAILED";

    private final OauthAccessTokenJpaRepository accessTokenRepository;
    private final JwtProperties jwtProperties;
    private final SnapResponseCodeMapper responseCodeMapper;
    private final Clock clock;

    public TokenIntrospectionService(
            OauthAccessTokenJpaRepository accessTokenRepository,
            JwtProperties jwtProperties,
            SnapResponseCodeMapper responseCodeMapper,
            Clock clock) {
        this.accessTokenRepository = accessTokenRepository;
        this.jwtProperties = jwtProperties;
        this.responseCodeMapper = responseCodeMapper;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public TokenIntrospectionResponse introspect(String rawToken) {
        if (!StringUtils.hasText(rawToken)) {
            return inactive();
        }

        SignedJWT signedJwt = parse(rawToken);
        if (signedJwt == null || !JWSAlgorithm.RS256.equals(signedJwt.getHeader().getAlgorithm())) {
            return inactive();
        }
        if (!verifySignature(signedJwt)) {
            return inactive();
        }

        JWTClaimsSet claims = claims(signedJwt);
        if (claims == null || !jwtProperties.getIssuer().equals(claims.getIssuer())) {
            return inactive();
        }

        String jti = claims.getJWTID();
        if (!StringUtils.hasText(jti) || claims.getExpirationTime() == null) {
            return inactive();
        }

        Instant now = clock.instant();
        if (!claims.getExpirationTime().toInstant().isAfter(now)) {
            throw invalidToken("TOKEN_EXPIRED");
        }

        OauthAccessTokenEntity metadata = findByJti(jti).orElse(null);
        if (metadata == null || !sha256Hex(rawToken).equals(metadata.getTokenHash())) {
            return inactive();
        }
        if (metadata.getExpiresAt() == null || !metadata.getExpiresAt().isAfter(now)) {
            throw invalidToken("TOKEN_METADATA_EXPIRED");
        }
        if (metadata.getRevokedAt() != null) {
            return inactive();
        }

        return new TokenIntrospectionResponse(
                true,
                metadata.getApiClient().getClientId(),
                metadata.getScopes(),
                metadata.getTokenType(),
                metadata.getExpiresAt(),
                metadata.getIssuedAt(),
                claims.getSubject(),
                Map.of("jti", jti));
    }

    private Optional<OauthAccessTokenEntity> findByJti(String jti) {
        try {
            return accessTokenRepository.findByTokenJti(jti);
        } catch (DataAccessException exception) {
            throw generalError(exception);
        } catch (RuntimeException exception) {
            throw generalError(exception);
        }
    }

    private SignedJWT parse(String rawToken) {
        try {
            return SignedJWT.parse(rawToken);
        } catch (ParseException exception) {
            return null;
        }
    }

    private boolean verifySignature(SignedJWT signedJwt) {
        try {
            JWSVerifier verifier = new RSASSAVerifier(parsePublicKey(jwtProperties.getPublicKey()));
            return signedJwt.verify(verifier);
        } catch (RuntimeException | GeneralSecurityException | com.nimbusds.jose.JOSEException exception) {
            return false;
        }
    }

    private JWTClaimsSet claims(SignedJWT signedJwt) {
        try {
            return signedJwt.getJWTClaimsSet();
        } catch (ParseException exception) {
            return null;
        }
    }

    private RSAPublicKey parsePublicKey(String publicKeyPem) throws GeneralSecurityException {
        if (!StringUtils.hasText(publicKeyPem)
                || !publicKeyPem.contains(BEGIN_PUBLIC_KEY)
                || !publicKeyPem.contains(END_PUBLIC_KEY)) {
            throw new GeneralSecurityException("JWT public key must be configured as X.509 PEM");
        }

        String base64PublicKey = publicKeyPem
                .replace("\\n", "\n")
                .replace(BEGIN_PUBLIC_KEY, "")
                .replace(END_PUBLIC_KEY, "")
                .replaceAll("\\s", "");
        byte[] publicKeyBytes = Base64.getDecoder().decode(base64PublicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        return (RSAPublicKey) KeyFactory.getInstance(RSA_KEY_FACTORY).generatePublic(keySpec);
    }

    private String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("SHA-256 digest is unavailable", exception);
        }
    }

    private TokenIntrospectionResponse inactive() {
        return new TokenIntrospectionResponse(false, null, null, null, null, null, null, Map.of());
    }

    private SnapUnauthorizedException invalidToken(String reason) {
        return new SnapUnauthorizedException(
                SnapUnauthorizedException.INVALID_TOKEN_RESPONSE_CODE,
                responseCodeMapper.resolvePublicMessage(SnapUnauthorizedException.INVALID_TOKEN_RESPONSE_CODE),
                reason);
    }

    private TokenMetadataPersistenceException generalError(RuntimeException cause) {
        return new TokenMetadataPersistenceException(
                responseCodeMapper.resolvePublicMessage(TokenMetadataPersistenceException.GENERAL_ERROR_RESPONSE_CODE),
                LOOKUP_FAILED_REASON,
                cause);
    }
}
