package com.portfolio.authservice.application.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.portfolio.authservice.application.credential.ClientCredential;
import com.portfolio.authservice.common.error.TokenMetadataPersistenceException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.infrastructure.persistence.entity.ApiClientEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.OauthAccessTokenEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.ResponseCodeMappingEntity;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiClientJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.OauthAccessTokenJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.test.util.ReflectionTestUtils;

class TokenMetadataServiceTests {

    private static final Instant NOW = Instant.parse("2026-05-07T08:00:00Z");
    private static final String RAW_TOKEN = "eyJhbGciOiJSUzI1NiJ9.payload.signature";

    private OauthAccessTokenJpaRepository accessTokenRepository;
    private ApiClientJpaRepository apiClientRepository;
    private ApiClientEntity apiClient;
    private TokenMetadataService service;

    @BeforeEach
    void setUp() {
        accessTokenRepository = mock(OauthAccessTokenJpaRepository.class);
        apiClientRepository = mock(ApiClientJpaRepository.class);
        apiClient = new ApiClientEntity();
        ReflectionTestUtils.setField(apiClient, "id", 1L);
        when(apiClientRepository.getReferenceById(1L)).thenReturn(apiClient);
        when(accessTokenRepository.save(any(OauthAccessTokenEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        service = new TokenMetadataService(
                accessTokenRepository,
                apiClientRepository,
                responseCodeMapper(),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void savesOnlyTokenMetadataAndNeverRawAccessToken() throws Exception {
        IssuedAccessToken issuedToken = issuedToken();

        service.saveIssuedToken(credential(), issuedToken);

        ArgumentCaptor<OauthAccessTokenEntity> tokenCaptor = ArgumentCaptor.forClass(OauthAccessTokenEntity.class);
        verify(accessTokenRepository).save(tokenCaptor.capture());
        OauthAccessTokenEntity metadata = tokenCaptor.getValue();
        assertThat(metadata.getApiClient()).isSameAs(apiClient);
        assertThat(metadata.getTokenJti()).isEqualTo("jti-123");
        assertThat(metadata.getTokenHash()).isEqualTo(sha256Hex(RAW_TOKEN));
        assertThat(metadata.getTokenType()).isEqualTo("Bearer");
        assertThat(metadata.getScopes()).isEqualTo("openid snap:auth:token");
        assertThat(metadata.getIssuedAt()).isEqualTo(NOW);
        assertThat(metadata.getExpiresAt()).isEqualTo(NOW.plusSeconds(900));
        assertThat(metadata.getRevokedAt()).isNull();
        assertThat(metadata.getTokenHash()).isNotEqualTo(RAW_TOKEN);
        assertThat(metadata.getTokenJti()).isNotEqualTo(RAW_TOKEN);
        assertThat(metadata.getScopes()).doesNotContain(RAW_TOKEN);
    }

    @Test
    void findsActiveMetadataByHashingRawToken() throws Exception {
        OauthAccessTokenEntity activeMetadata = new OauthAccessTokenEntity();
        when(accessTokenRepository.findActiveByTokenHash(sha256Hex(RAW_TOKEN), NOW))
                .thenReturn(Optional.of(activeMetadata));

        Optional<OauthAccessTokenEntity> result = service.findActiveByRawToken(RAW_TOKEN);

        assertThat(result).containsSame(activeMetadata);
        verify(accessTokenRepository).findActiveByTokenHash(sha256Hex(RAW_TOKEN), NOW);
    }

    @Test
    void returnsEmptyForBlankRawTokenWithoutRepositoryLookup() {
        assertThat(service.findActiveByRawToken(" ")).isEmpty();
    }

    @Test
    void mapsSaveFailureToGeneralError() {
        when(accessTokenRepository.save(any(OauthAccessTokenEntity.class)))
                .thenThrow(new DataAccessResourceFailureException("database unavailable"));

        assertThatThrownBy(() -> service.saveIssuedToken(credential(), issuedToken()))
                .isInstanceOfSatisfying(TokenMetadataPersistenceException.class, exception -> {
                    assertThat(exception.getResponseCode()).isEqualTo("5007300");
                    assertThat(exception.getResponseMessage()).isEqualTo("General Error");
                    assertThat(exception.getReason()).isEqualTo("TOKEN_METADATA_SAVE_FAILED");
                });
    }

    @Test
    void mapsLookupFailureToGeneralError() {
        when(accessTokenRepository.findActiveByTokenHash(eq(sha256Hex(RAW_TOKEN)), eq(NOW)))
                .thenThrow(new DataAccessResourceFailureException("database unavailable"));

        assertThatThrownBy(() -> service.findActiveByRawToken(RAW_TOKEN))
                .isInstanceOfSatisfying(TokenMetadataPersistenceException.class, exception -> {
                    assertThat(exception.getResponseCode()).isEqualTo("5007300");
                    assertThat(exception.getResponseMessage()).isEqualTo("General Error");
                    assertThat(exception.getReason()).isEqualTo("TOKEN_METADATA_LOOKUP_FAILED");
                });
    }

    private ClientCredential credential() {
        return new ClientCredential(
                1L,
                "client-id",
                "MERCHANT-001",
                "95221",
                900,
                "public-key-pem",
                "SHA256withRSA",
                "key-1",
                List.of("openid", "snap:auth:token"));
    }

    private IssuedAccessToken issuedToken() {
        return new IssuedAccessToken(
                RAW_TOKEN,
                "Bearer",
                "900",
                "jti-123",
                NOW,
                NOW.plusSeconds(900),
                List.of("openid", "snap:auth:token"));
    }

    private String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    @SuppressWarnings("unchecked")
    private SnapResponseCodeMapper responseCodeMapper() {
        ResponseCodeMappingEntity mapping = new ResponseCodeMappingEntity();
        mapping.setResponseMessage("General Error");

        ResponseCodeMappingJpaRepository repository = mock(ResponseCodeMappingJpaRepository.class);
        when(repository.findByResponseCode("5007300")).thenReturn(Optional.of(mapping));

        ObjectProvider<ResponseCodeMappingJpaRepository> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(repository);
        return new SnapResponseCodeMapper(provider);
    }
}
