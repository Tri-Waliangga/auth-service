package com.portfolio.authservice.application.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.portfolio.authservice.common.error.SnapUnauthorizedException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.config.JwtProperties;
import com.portfolio.authservice.infrastructure.persistence.entity.ApiClientEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.OauthAccessTokenEntity;
import com.portfolio.authservice.infrastructure.persistence.repository.OauthAccessTokenJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import com.portfolio.authservice.interfaces.rest.dto.TokenIntrospectionResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

class TokenIntrospectionServiceTests {

    private static final Instant NOW = Instant.parse("2026-05-07T08:00:00Z");

    private OauthAccessTokenJpaRepository accessTokenRepository;
    private KeyPair signingKeyPair;
    private TokenIntrospectionService service;

    @BeforeEach
    void setUp() throws Exception {
        accessTokenRepository = mock(OauthAccessTokenJpaRepository.class);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        signingKeyPair = generator.generateKeyPair();

        service = new TokenIntrospectionService(
                accessTokenRepository,
                jwtProperties(signingKeyPair),
                responseCodeMapper(),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void activeTokenReturnsMetadataBackToCaller() throws Exception {
        String token = signedToken(signingKeyPair, "jti-1", NOW.plusSeconds(600), "auth-service-test");
        OauthAccessTokenEntity metadata = metadata(token, NOW.plusSeconds(600));
        when(accessTokenRepository.findByTokenJti("jti-1")).thenReturn(Optional.of(metadata));

        TokenIntrospectionResponse response = service.introspect(token);

        assertThat(response.active()).isTrue();
        assertThat(response.clientId()).isEqualTo("client-id");
        assertThat(response.scope()).isEqualTo("openid snap:auth:token");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresAt()).isEqualTo(NOW.plusSeconds(600));
        assertThat(response.issuedAt()).isEqualTo(NOW);
        assertThat(response.subject()).isEqualTo("client-id");
        assertThat(response.additionalInfo()).containsEntry("jti", "jti-1");
    }

    @Test
    void expiredJwtThrowsInvalidTokenSnapError() throws Exception {
        String token = signedToken(signingKeyPair, "jti-1", NOW.minusSeconds(1), "auth-service-test");

        assertThatThrownBy(() -> service.introspect(token))
                .isInstanceOfSatisfying(SnapUnauthorizedException.class, exception -> {
                    assertThat(exception.getResponseCode()).isEqualTo("4017301");
                    assertThat(exception.getResponseMessage()).isEqualTo("Invalid Token (B2B)");
                    assertThat(exception.getReason()).isEqualTo("TOKEN_EXPIRED");
                });
        verifyNoInteractions(accessTokenRepository);
    }

    @Test
    void revokedTokenReturnsInactive() throws Exception {
        String token = signedToken(signingKeyPair, "jti-1", NOW.plusSeconds(600), "auth-service-test");
        OauthAccessTokenEntity metadata = metadata(token, NOW.plusSeconds(600));
        metadata.setRevokedAt(NOW.plusSeconds(60));
        when(accessTokenRepository.findByTokenJti("jti-1")).thenReturn(Optional.of(metadata));

        assertThat(service.introspect(token).active()).isFalse();
    }

    @Test
    void unknownJtiReturnsInactive() throws Exception {
        String token = signedToken(signingKeyPair, "jti-1", NOW.plusSeconds(600), "auth-service-test");
        when(accessTokenRepository.findByTokenJti("jti-1")).thenReturn(Optional.empty());

        assertThat(service.introspect(token).active()).isFalse();
    }

    @Test
    void badSignatureReturnsInactive() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair otherKeyPair = generator.generateKeyPair();

        String token = signedToken(otherKeyPair, "jti-1", NOW.plusSeconds(600), "auth-service-test");

        assertThat(service.introspect(token).active()).isFalse();
        verifyNoInteractions(accessTokenRepository);
    }

    @Test
    void malformedTokenReturnsInactive() {
        assertThat(service.introspect("not-a-jwt").active()).isFalse();
        verifyNoInteractions(accessTokenRepository);
    }

    @Test
    void hashMismatchReturnsInactive() throws Exception {
        String token = signedToken(signingKeyPair, "jti-1", NOW.plusSeconds(600), "auth-service-test");
        OauthAccessTokenEntity metadata = metadata("different-token", NOW.plusSeconds(600));
        when(accessTokenRepository.findByTokenJti("jti-1")).thenReturn(Optional.of(metadata));

        assertThat(service.introspect(token).active()).isFalse();
    }

    @Test
    void expiredMetadataThrowsInvalidTokenSnapError() throws Exception {
        String token = signedToken(signingKeyPair, "jti-1", NOW.plusSeconds(600), "auth-service-test");
        OauthAccessTokenEntity metadata = metadata(token, NOW.minusSeconds(1));
        when(accessTokenRepository.findByTokenJti("jti-1")).thenReturn(Optional.of(metadata));

        assertThatThrownBy(() -> service.introspect(token))
                .isInstanceOfSatisfying(SnapUnauthorizedException.class, exception -> {
                    assertThat(exception.getResponseCode()).isEqualTo("4017301");
                    assertThat(exception.getReason()).isEqualTo("TOKEN_METADATA_EXPIRED");
                });
    }

    private String signedToken(KeyPair keyPair, String jti, Instant expiresAt, String issuer) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .jwtID(jti)
                .issuer(issuer)
                .subject("client-id")
                .issueTime(Date.from(NOW))
                .expirationTime(Date.from(expiresAt))
                .claim("client_id", "client-id")
                .claim("scope", "openid snap:auth:token")
                .build();
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
        jwt.sign(new RSASSASigner(keyPair.getPrivate()));
        return jwt.serialize();
    }

    private OauthAccessTokenEntity metadata(String rawToken, Instant expiresAt) throws Exception {
        ApiClientEntity apiClient = new ApiClientEntity();
        apiClient.setClientId("client-id");

        OauthAccessTokenEntity metadata = new OauthAccessTokenEntity();
        metadata.setApiClient(apiClient);
        metadata.setTokenJti("jti-1");
        metadata.setTokenHash(sha256Hex(rawToken));
        metadata.setTokenType("Bearer");
        metadata.setScopes("openid snap:auth:token");
        metadata.setIssuedAt(NOW);
        metadata.setExpiresAt(expiresAt);
        return metadata;
    }

    private JwtProperties jwtProperties(KeyPair keyPair) {
        JwtProperties properties = new JwtProperties();
        properties.setIssuer("auth-service-test");
        properties.setPublicKey(toPublicKeyPem(keyPair).replace("\n", "\\n"));
        return properties;
    }

    private String toPublicKeyPem(KeyPair keyPair) {
        String encodedKey = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(keyPair.getPublic().getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + encodedKey + "\n-----END PUBLIC KEY-----";
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
