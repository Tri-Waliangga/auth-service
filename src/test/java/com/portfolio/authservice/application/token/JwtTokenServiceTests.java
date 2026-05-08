package com.portfolio.authservice.application.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.portfolio.authservice.application.credential.ClientCredential;
import com.portfolio.authservice.config.JwtProperties;
import com.portfolio.authservice.infrastructure.persistence.entity.ApiClientEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.OauthAccessTokenEntity;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiClientJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.OauthAccessTokenJpaRepository;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

class JwtTokenServiceTests {

    private static final Instant NOW = Instant.parse("2026-05-07T08:00:00Z");

    private OauthAccessTokenJpaRepository accessTokenRepository;
    private ApiClientJpaRepository apiClientRepository;
    private ApiClientEntity apiClient;
    private KeyPair keyPair;
    private JwtTokenService service;

    @BeforeEach
    void setUp() throws Exception {
        accessTokenRepository = mock(OauthAccessTokenJpaRepository.class);
        apiClientRepository = mock(ApiClientJpaRepository.class);
        apiClient = new ApiClientEntity();
        ReflectionTestUtils.setField(apiClient, "id", 1L);
        when(apiClientRepository.getReferenceById(1L)).thenReturn(apiClient);
        when(accessTokenRepository.save(any(OauthAccessTokenEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();

        service = new JwtTokenService(
                jwtProperties(900),
                accessTokenRepository,
                apiClientRepository,
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void issuesSignedBearerJwtAndStoresMetadata() throws Exception {
        ClientCredential credential = credential(600);

        IssuedAccessToken issuedToken = service.issueAccessToken(credential);

        assertThat(issuedToken.accessToken()).isNotBlank();
        assertThat(issuedToken.tokenType()).isEqualTo("Bearer");
        assertThat(issuedToken.expiresIn()).isEqualTo("600");
        assertThat(issuedToken.issuedAt()).isEqualTo(NOW);
        assertThat(issuedToken.expiresAt()).isEqualTo(NOW.plusSeconds(600));
        assertThat(issuedToken.scopes()).containsExactly("openid", "snap:auth:token");

        SignedJWT signedJwt = SignedJWT.parse(issuedToken.accessToken());
        assertThat(signedJwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(signedJwt.verify(new RSASSAVerifier((RSAPublicKey) keyPair.getPublic()))).isTrue();
        assertThat(signedJwt.getJWTClaimsSet().getJWTID()).isEqualTo(issuedToken.jti());
        assertThat(signedJwt.getJWTClaimsSet().getIssuer()).isEqualTo("auth-service-test");
        assertThat(signedJwt.getJWTClaimsSet().getSubject()).isEqualTo("client-id");
        assertThat(signedJwt.getJWTClaimsSet().getStringClaim("client_id")).isEqualTo("client-id");
        assertThat(signedJwt.getJWTClaimsSet().getStringClaim("merchant_code")).isEqualTo("MERCHANT-001");
        assertThat(signedJwt.getJWTClaimsSet().getStringClaim("channel_id")).isEqualTo("95221");
        assertThat(signedJwt.getJWTClaimsSet().getStringClaim("scope")).isEqualTo("openid snap:auth:token");
        assertThat(signedJwt.getJWTClaimsSet().getIssueTime().toInstant()).isEqualTo(NOW);
        assertThat(signedJwt.getJWTClaimsSet().getExpirationTime().toInstant()).isEqualTo(NOW.plusSeconds(600));

        ArgumentCaptor<OauthAccessTokenEntity> tokenCaptor = ArgumentCaptor.forClass(OauthAccessTokenEntity.class);
        verify(accessTokenRepository).save(tokenCaptor.capture());
        OauthAccessTokenEntity tokenMetadata = tokenCaptor.getValue();
        assertThat(tokenMetadata.getApiClient()).isSameAs(apiClient);
        assertThat(tokenMetadata.getTokenJti()).isEqualTo(issuedToken.jti());
        assertThat(tokenMetadata.getTokenHash()).isEqualTo(sha256Hex(issuedToken.accessToken()));
        assertThat(tokenMetadata.getTokenType()).isEqualTo("Bearer");
        assertThat(tokenMetadata.getScopes()).isEqualTo("openid snap:auth:token");
        assertThat(tokenMetadata.getIssuedAt()).isEqualTo(NOW);
        assertThat(tokenMetadata.getExpiresAt()).isEqualTo(NOW.plusSeconds(600));
    }

    @Test
    void usesConfiguredDefaultTtlWhenClientTtlIsNullOrNonPositive() {
        service = new JwtTokenService(
                jwtProperties(1200),
                accessTokenRepository,
                apiClientRepository,
                Clock.fixed(NOW, ZoneOffset.UTC));

        IssuedAccessToken nullTtlToken = service.issueAccessToken(credential(null));
        IssuedAccessToken nonPositiveTtlToken = service.issueAccessToken(credential(0));

        assertThat(nullTtlToken.expiresIn()).isEqualTo("1200");
        assertThat(nullTtlToken.expiresAt()).isEqualTo(NOW.plusSeconds(1200));
        assertThat(nonPositiveTtlToken.expiresIn()).isEqualTo("1200");
        assertThat(nonPositiveTtlToken.expiresAt()).isEqualTo(NOW.plusSeconds(1200));
    }

    private ClientCredential credential(Integer tokenTtlSeconds) {
        return new ClientCredential(
                1L,
                "client-id",
                "MERCHANT-001",
                "95221",
                tokenTtlSeconds,
                "public-key-pem",
                "SHA256withRSA",
                "key-1",
                List.of("openid", "snap:auth:token"));
    }

    private JwtProperties jwtProperties(Integer defaultTokenTtlSeconds) {
        JwtProperties properties = new JwtProperties();
        properties.setIssuer("auth-service-test");
        properties.setPrivateKey(toPrivateKeyPem().replace("\n", "\\n"));
        properties.setPublicKey("unused-public-key");
        properties.setDefaultTokenTtlSeconds(defaultTokenTtlSeconds);
        return properties;
    }

    private String toPrivateKeyPem() {
        String encodedKey = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(keyPair.getPrivate().getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + encodedKey + "\n-----END PRIVATE KEY-----";
    }

    private String sha256Hex(String value) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
    }
}
