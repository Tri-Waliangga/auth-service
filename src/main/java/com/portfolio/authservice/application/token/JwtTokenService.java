package com.portfolio.authservice.application.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.portfolio.authservice.application.credential.ClientCredential;
import com.portfolio.authservice.config.JwtProperties;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiClientJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.OauthAccessTokenJpaRepository;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

@Service
@ConditionalOnBean({
        ApiClientJpaRepository.class,
        OauthAccessTokenJpaRepository.class
})
public class JwtTokenService {

    private static final String TOKEN_TYPE = "Bearer";
    private static final String RSA_KEY_FACTORY = "RSA";
    private static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
    private static final String END_PRIVATE_KEY = "-----END PRIVATE KEY-----";

    private final JwtProperties jwtProperties;
    private final TokenMetadataService tokenMetadataService;
    private final Clock clock;

    public JwtTokenService(
            JwtProperties jwtProperties,
            TokenMetadataService tokenMetadataService,
            Clock clock) {
        this.jwtProperties = jwtProperties;
        this.tokenMetadataService = tokenMetadataService;
        this.clock = clock;
    }

    @Transactional
    public IssuedAccessToken issueAccessToken(ClientCredential credential) {
        validateCredential(credential);

        int ttlSeconds = resolveTtlSeconds(credential);
        Instant issuedAt = clock.instant();
        Instant expiresAt = issuedAt.plusSeconds(ttlSeconds);
        String jti = UUID.randomUUID().toString();
        List<String> scopes = List.copyOf(credential.scopes());
        String scopeClaim = String.join(" ", scopes);

        IssuedAccessToken issuedToken = new IssuedAccessToken(
                signJwt(credential, jti, issuedAt, expiresAt, scopeClaim),
                TOKEN_TYPE,
                String.valueOf(ttlSeconds),
                jti,
                issuedAt,
                expiresAt,
                scopes);
        tokenMetadataService.saveIssuedToken(credential, issuedToken);
        return issuedToken;
    }

    private String signJwt(
            ClientCredential credential,
            String jti,
            Instant issuedAt,
            Instant expiresAt,
            String scopeClaim) {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID(jti)
                .issuer(jwtProperties.getIssuer())
                .subject(credential.clientId())
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiresAt))
                .claim("client_id", credential.clientId())
                .claim("merchant_code", credential.merchantCode())
                .claim("channel_id", credential.channelId())
                .claim("scope", scopeClaim)
                .build();

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
        try {
            jwt.sign(new RSASSASigner(parsePrivateKey(jwtProperties.getPrivateKey())));
            return jwt.serialize();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Failed to sign JWT access token", exception);
        }
    }

    private int resolveTtlSeconds(ClientCredential credential) {
        Integer clientTtlSeconds = credential.tokenTtlSeconds();
        if (clientTtlSeconds != null && clientTtlSeconds > 0) {
            return clientTtlSeconds;
        }

        Integer defaultTtlSeconds = jwtProperties.getDefaultTokenTtlSeconds();
        if (defaultTtlSeconds != null && defaultTtlSeconds > 0) {
            return defaultTtlSeconds;
        }
        return 900;
    }

    private RSAPrivateKey parsePrivateKey(String privateKeyPem) {
        if (!StringUtils.hasText(privateKeyPem)
                || !privateKeyPem.contains(BEGIN_PRIVATE_KEY)
                || !privateKeyPem.contains(END_PRIVATE_KEY)) {
            throw new IllegalStateException("JWT private key must be configured as PKCS#8 PEM");
        }

        String base64PrivateKey = privateKeyPem
                .replace("\\n", "\n")
                .replace(BEGIN_PRIVATE_KEY, "")
                .replace(END_PRIVATE_KEY, "")
                .replaceAll("\\s", "");

        try {
            byte[] privateKeyBytes = Base64.getDecoder().decode(base64PrivateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            return (RSAPrivateKey) KeyFactory.getInstance(RSA_KEY_FACTORY).generatePrivate(keySpec);
        } catch (IllegalArgumentException | GeneralSecurityException exception) {
            throw new IllegalStateException("JWT private key must be a valid PKCS#8 RSA PEM", exception);
        }
    }

    private void validateCredential(ClientCredential credential) {
        if (credential == null
                || credential.apiClientId() == null
                || !StringUtils.hasText(credential.clientId())
                || !StringUtils.hasText(credential.merchantCode())
                || credential.scopes() == null) {
            throw new IllegalArgumentException("Client credential is incomplete");
        }
    }
}
