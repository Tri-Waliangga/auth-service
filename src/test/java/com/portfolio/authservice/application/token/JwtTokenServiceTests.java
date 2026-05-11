package com.portfolio.authservice.application.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.portfolio.authservice.application.credential.ClientCredential;
import com.portfolio.authservice.common.error.TokenMetadataPersistenceException;
import com.portfolio.authservice.config.JwtProperties;
import com.portfolio.authservice.support.TestCryptoFixtures;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JwtTokenServiceTests {

    private static final Instant NOW = Instant.parse("2026-05-07T08:00:00Z");

    private TokenMetadataService tokenMetadataService;
    private JwtTokenService service;

    @BeforeEach
    void setUp() {
        tokenMetadataService = mock(TokenMetadataService.class);

        service = new JwtTokenService(
                jwtProperties(900),
                tokenMetadataService,
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
        assertThat(signedJwt.verify(new RSASSAVerifier(TestCryptoFixtures.publicKey()))).isTrue();
        assertThat(signedJwt.getJWTClaimsSet().getJWTID()).isEqualTo(issuedToken.jti());
        assertThat(signedJwt.getJWTClaimsSet().getIssuer()).isEqualTo("auth-service-test");
        assertThat(signedJwt.getJWTClaimsSet().getSubject()).isEqualTo("client-id");
        assertThat(signedJwt.getJWTClaimsSet().getStringClaim("client_id")).isEqualTo("client-id");
        assertThat(signedJwt.getJWTClaimsSet().getStringClaim("merchant_code")).isEqualTo("MERCHANT-001");
        assertThat(signedJwt.getJWTClaimsSet().getStringClaim("channel_id")).isEqualTo("95221");
        assertThat(signedJwt.getJWTClaimsSet().getStringClaim("scope")).isEqualTo("openid snap:auth:token");
        assertThat(signedJwt.getJWTClaimsSet().getIssueTime().toInstant()).isEqualTo(NOW);
        assertThat(signedJwt.getJWTClaimsSet().getExpirationTime().toInstant()).isEqualTo(NOW.plusSeconds(600));

        verify(tokenMetadataService).saveIssuedToken(eq(credential), eq(issuedToken));
    }

    @Test
    void usesConfiguredDefaultTtlWhenClientTtlIsNullOrNonPositive() {
        service = new JwtTokenService(
                jwtProperties(1200),
                tokenMetadataService,
                Clock.fixed(NOW, ZoneOffset.UTC));

        IssuedAccessToken nullTtlToken = service.issueAccessToken(credential(null));
        IssuedAccessToken nonPositiveTtlToken = service.issueAccessToken(credential(0));

        assertThat(nullTtlToken.expiresIn()).isEqualTo("1200");
        assertThat(nullTtlToken.expiresAt()).isEqualTo(NOW.plusSeconds(1200));
        assertThat(nonPositiveTtlToken.expiresIn()).isEqualTo("1200");
        assertThat(nonPositiveTtlToken.expiresAt()).isEqualTo(NOW.plusSeconds(1200));
    }

    @Test
    void propagatesMetadataPersistenceFailureWithoutReturningToken() {
        ClientCredential credential = credential(600);
        TokenMetadataPersistenceException persistenceException = new TokenMetadataPersistenceException(
                "General Error",
                "TOKEN_METADATA_SAVE_FAILED",
                new RuntimeException("database unavailable"));
        doThrow(persistenceException).when(tokenMetadataService).saveIssuedToken(eq(credential), org.mockito.ArgumentMatchers.any());

        assertThatThrownBy(() -> service.issueAccessToken(credential))
                .isSameAs(persistenceException)
                .isInstanceOfSatisfying(TokenMetadataPersistenceException.class, exception -> {
                    assertThat(exception.getResponseCode()).isEqualTo("5007300");
                    assertThat(exception.getResponseMessage()).isEqualTo("General Error");
                    assertThat(exception.getReason()).isEqualTo("TOKEN_METADATA_SAVE_FAILED");
                });
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
        properties.setPrivateKey(TestCryptoFixtures.escapedPrivateKeyPem());
        properties.setPublicKey("unused-public-key");
        properties.setDefaultTokenTtlSeconds(defaultTokenTtlSeconds);
        return properties;
    }

}
