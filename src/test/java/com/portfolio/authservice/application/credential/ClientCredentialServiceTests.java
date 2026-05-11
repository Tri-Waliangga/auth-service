package com.portfolio.authservice.application.credential;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.infrastructure.persistence.entity.ApiClientEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.ClientPublicKeyEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.ClientScopeEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.MerchantEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.ResponseCodeMappingEntity;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiClientJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ClientPublicKeyJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ClientScopeJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.test.util.ReflectionTestUtils;

class ClientCredentialServiceTests {

    private static final Instant NOW = Instant.parse("2026-05-07T08:00:00Z");

    private ApiClientJpaRepository apiClientRepository;
    private ClientPublicKeyJpaRepository publicKeyRepository;
    private ClientScopeJpaRepository scopeRepository;
    private ClientCredentialService service;

    @BeforeEach
    void setUp() {
        apiClientRepository = mock(ApiClientJpaRepository.class);
        publicKeyRepository = mock(ClientPublicKeyJpaRepository.class);
        scopeRepository = mock(ClientScopeJpaRepository.class);
        service = new ClientCredentialService(
                apiClientRepository,
                publicKeyRepository,
                scopeRepository,
                responseCodeMapper(),
                Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void loadsActiveClientCredential() {
        ApiClientEntity client = activeClient("0.0.0.0/0");
        ClientPublicKeyEntity publicKey = publicKey();
        ClientScopeEntity openid = scope("openid");
        ClientScopeEntity tokenScope = scope("snap:auth:token");
        when(apiClientRepository.findByClientId("client-id")).thenReturn(Optional.of(client));
        when(publicKeyRepository.findActivePublicKeyByClient(1L, NOW)).thenReturn(Optional.of(publicKey));
        when(scopeRepository.findByApiClientIdAndIsActiveTrue(1L)).thenReturn(List.of(openid, tokenScope));

        ClientCredential credential = service.loadActiveClientCredential("client-id", "10.10.10.10");

        assertThat(credential.apiClientId()).isEqualTo(1L);
        assertThat(credential.clientId()).isEqualTo("client-id");
        assertThat(credential.merchantCode()).isEqualTo("MERCHANT-001");
        assertThat(credential.channelId()).isEqualTo("95221");
        assertThat(credential.tokenTtlSeconds()).isEqualTo(900);
        assertThat(credential.publicKeyPem()).isEqualTo("public-key-pem");
        assertThat(credential.publicKeyAlgorithm()).isEqualTo("SHA256withRSA");
        assertThat(credential.publicKeyId()).isEqualTo("key-1");
        assertThat(credential.scopes()).containsExactly("openid", "snap:auth:token");
        verify(publicKeyRepository).findActivePublicKeyByClient(1L, NOW);
    }

    @Test
    void acceptsExactIpPolicy() {
        givenValidCredential("192.168.1.10");

        assertThat(service.loadActiveClientCredential("client-id", "192.168.1.10")).isNotNull();
    }

    @Test
    void acceptsCommaSeparatedCidrPolicy() {
        givenValidCredential("10.0.0.0/8, 192.168.1.0/24");

        assertThat(service.loadActiveClientCredential("client-id", "192.168.1.25")).isNotNull();
    }

    @Test
    void rejectsUnknownClientWithoutPublicDetail() {
        when(apiClientRepository.findByClientId("client-id")).thenReturn(Optional.empty());

        assertCredentialFailure(ClientCredentialFailureReason.CLIENT_NOT_FOUND);
    }

    @Test
    void rejectsInactiveClientWithoutPublicDetail() {
        ApiClientEntity client = activeClient("0.0.0.0/0");
        client.setStatus("INACTIVE");
        when(apiClientRepository.findByClientId("client-id")).thenReturn(Optional.of(client));

        assertCredentialFailure(ClientCredentialFailureReason.CLIENT_INACTIVE);
    }

    @Test
    void rejectsMissingRemoteIp() {
        givenValidCredential("0.0.0.0/0");

        assertCredentialFailure(" ", ClientCredentialFailureReason.REMOTE_IP_MISSING);
    }

    @Test
    void rejectsMissingIpPolicy() {
        givenValidCredential(null);

        assertCredentialFailure(ClientCredentialFailureReason.IP_POLICY_MISSING);
    }

    @Test
    void rejectsInvalidIpPolicy() {
        givenValidCredential("10.0.0.0/33");

        assertCredentialFailure(ClientCredentialFailureReason.IP_POLICY_INVALID);
    }

    @Test
    void rejectsIpOutsidePolicy() {
        givenValidCredential("192.168.1.0/24");

        assertCredentialFailure(ClientCredentialFailureReason.IP_NOT_ALLOWED);
    }

    @Test
    void rejectsUnavailablePublicKey() {
        ApiClientEntity client = activeClient("0.0.0.0/0");
        when(apiClientRepository.findByClientId("client-id")).thenReturn(Optional.of(client));
        when(publicKeyRepository.findActivePublicKeyByClient(1L, NOW)).thenReturn(Optional.empty());

        assertCredentialFailure(ClientCredentialFailureReason.PUBLIC_KEY_UNAVAILABLE);
    }

    @Test
    void rejectsExpiredPublicKeyWhenNoKeyIsActiveAtCurrentTime() {
        ApiClientEntity client = activeClient("0.0.0.0/0");
        when(apiClientRepository.findByClientId("client-id")).thenReturn(Optional.of(client));
        when(publicKeyRepository.findActivePublicKeyByClient(1L, NOW)).thenReturn(Optional.empty());

        assertCredentialFailure(ClientCredentialFailureReason.PUBLIC_KEY_UNAVAILABLE);
        verify(publicKeyRepository).findActivePublicKeyByClient(1L, NOW);
    }

    @Test
    void rejectsEmptyScopes() {
        ApiClientEntity client = activeClient("0.0.0.0/0");
        when(apiClientRepository.findByClientId("client-id")).thenReturn(Optional.of(client));
        when(publicKeyRepository.findActivePublicKeyByClient(1L, NOW)).thenReturn(Optional.of(publicKey()));
        when(scopeRepository.findByApiClientIdAndIsActiveTrue(1L)).thenReturn(List.of());

        assertCredentialFailure(ClientCredentialFailureReason.NO_ACTIVE_SCOPE);
    }

    private void givenValidCredential(String allowedIpCidr) {
        ApiClientEntity client = activeClient(allowedIpCidr);
        when(apiClientRepository.findByClientId("client-id")).thenReturn(Optional.of(client));
        when(publicKeyRepository.findActivePublicKeyByClient(1L, NOW)).thenReturn(Optional.of(publicKey()));
        when(scopeRepository.findByApiClientIdAndIsActiveTrue(1L)).thenReturn(List.of(scope("openid")));
    }

    private ApiClientEntity activeClient(String allowedIpCidr) {
        ApiClientEntity client = new ApiClientEntity();
        ReflectionTestUtils.setField(client, "id", 1L);
        client.setClientId("client-id");
        client.setChannelId("95221");
        client.setTokenTtlSeconds(900);
        client.setAllowedIpCidr(allowedIpCidr);
        client.setStatus("ACTIVE");
        client.setMerchant(merchant());
        return client;
    }

    private MerchantEntity merchant() {
        MerchantEntity merchant = new MerchantEntity();
        merchant.setMerchantCode("MERCHANT-001");
        merchant.setMerchantName("Merchant One");
        merchant.setStatus("ACTIVE");
        return merchant;
    }

    private ClientPublicKeyEntity publicKey() {
        ClientPublicKeyEntity publicKey = new ClientPublicKeyEntity();
        publicKey.setKeyId("key-1");
        publicKey.setPublicKeyPem("public-key-pem");
        publicKey.setAlgorithm("SHA256withRSA");
        return publicKey;
    }

    private ClientScopeEntity scope(String scopeCode) {
        ClientScopeEntity scope = new ClientScopeEntity();
        scope.setScopeCode(scopeCode);
        return scope;
    }

    private void assertCredentialFailure(ClientCredentialFailureReason failureReason) {
        assertCredentialFailure("10.10.10.10", failureReason);
    }

    private void assertCredentialFailure(String remoteIp, ClientCredentialFailureReason failureReason) {
        assertThatThrownBy(() -> service.loadActiveClientCredential("client-id", remoteIp))
                .isInstanceOfSatisfying(ClientCredentialException.class, exception -> {
                    assertThat(exception.getResponseCode()).isEqualTo("4017300");
                    assertThat(exception.getResponseMessage()).isEqualTo("Unauthorized");
                    assertThat(exception.getFailureReason()).isEqualTo(failureReason);
                });
    }

    @SuppressWarnings("unchecked")
    private SnapResponseCodeMapper responseCodeMapper() {
        ResponseCodeMappingEntity mapping = new ResponseCodeMappingEntity();
        mapping.setResponseMessage("Unauthorized. [reason]");

        ResponseCodeMappingJpaRepository repository = mock(ResponseCodeMappingJpaRepository.class);
        when(repository.findByResponseCode(any())).thenReturn(Optional.empty());
        when(repository.findByResponseCode("4017300")).thenReturn(Optional.of(mapping));

        ObjectProvider<ResponseCodeMappingJpaRepository> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(repository);
        return new SnapResponseCodeMapper(provider);
    }
}
