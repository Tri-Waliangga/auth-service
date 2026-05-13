package com.portfolio.authservice.application.credential;

import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.infrastructure.persistence.entity.ApiClientEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.ClientPublicKeyEntity;
import com.portfolio.authservice.infrastructure.persistence.entity.ClientScopeEntity;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiClientJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ClientPublicKeyJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ClientScopeJpaRepository;
import java.time.Clock;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class ClientCredentialService {

    private static final String ACTIVE_STATUS = "ACTIVE";

    private final ApiClientJpaRepository apiClientRepository;
    private final ClientPublicKeyJpaRepository publicKeyRepository;
    private final ClientScopeJpaRepository scopeRepository;
    private final SnapResponseCodeMapper responseCodeMapper;
    private final Clock clock;

    public ClientCredentialService(
            ApiClientJpaRepository apiClientRepository,
            ClientPublicKeyJpaRepository publicKeyRepository,
            ClientScopeJpaRepository scopeRepository,
            SnapResponseCodeMapper responseCodeMapper,
            Clock clock) {
        this.apiClientRepository = apiClientRepository;
        this.publicKeyRepository = publicKeyRepository;
        this.scopeRepository = scopeRepository;
        this.responseCodeMapper = responseCodeMapper;
        this.clock = clock;
    }

    public ClientCredential loadActiveClientCredential(String clientId, String remoteIp) {
        ApiClientEntity apiClient = apiClientRepository.findByClientId(clientId)
                .orElseThrow(() -> unauthorized(ClientCredentialFailureReason.CLIENT_NOT_FOUND));

        if (!ACTIVE_STATUS.equals(apiClient.getStatus())) {
            throw unauthorized(ClientCredentialFailureReason.CLIENT_INACTIVE);
        }

        validateIpPolicy(apiClient.getAllowedIpCidr(), remoteIp);

        ClientPublicKeyEntity publicKey = publicKeyRepository
                .findActivePublicKeyByClient(apiClient.getId(), clock.instant())
                .orElseThrow(() -> unauthorized(ClientCredentialFailureReason.PUBLIC_KEY_UNAVAILABLE));

        List<String> scopes = scopeRepository.findByApiClientIdAndIsActiveTrue(apiClient.getId()).stream()
                .map(ClientScopeEntity::getScopeCode)
                .toList();
        if (scopes.isEmpty()) {
            throw unauthorized(ClientCredentialFailureReason.NO_ACTIVE_SCOPE);
        }

        return new ClientCredential(
                apiClient.getId(),
                apiClient.getClientId(),
                apiClient.getMerchant().getMerchantCode(),
                apiClient.getChannelId(),
                apiClient.getTokenTtlSeconds(),
                publicKey.getPublicKeyPem(),
                publicKey.getAlgorithm(),
                publicKey.getKeyId(),
                List.copyOf(scopes));
    }

    private void validateIpPolicy(String allowedIpCidr, String remoteIp) {
        if (!StringUtils.hasText(remoteIp)) {
            throw unauthorized(ClientCredentialFailureReason.REMOTE_IP_MISSING);
        }
        if (!StringUtils.hasText(allowedIpCidr)) {
            throw unauthorized(ClientCredentialFailureReason.IP_POLICY_MISSING);
        }

        long remoteIpValue = parseIpv4(remoteIp.trim());
        boolean allowed = false;
        for (String policyEntry : allowedIpCidr.split(",")) {
            String trimmedPolicy = policyEntry.trim();
            if (!StringUtils.hasText(trimmedPolicy)) {
                continue;
            }
            if (isPolicyMatch(trimmedPolicy, remoteIpValue)) {
                allowed = true;
                break;
            }
        }

        if (!allowed) {
            throw unauthorized(ClientCredentialFailureReason.IP_NOT_ALLOWED);
        }
    }

    private boolean isPolicyMatch(String policyEntry, long remoteIpValue) {
        if (!policyEntry.contains("/")) {
            return parseIpv4(policyEntry) == remoteIpValue;
        }

        String[] cidrParts = policyEntry.split("/", -1);
        if (cidrParts.length != 2 || !StringUtils.hasText(cidrParts[0]) || !StringUtils.hasText(cidrParts[1])) {
            throw unauthorized(ClientCredentialFailureReason.IP_POLICY_INVALID);
        }

        long networkAddress = parseIpv4(cidrParts[0]);
        int prefixLength = parsePrefixLength(cidrParts[1]);
        long mask = prefixLength == 0 ? 0L : (0xFFFFFFFFL << (32 - prefixLength)) & 0xFFFFFFFFL;
        return (remoteIpValue & mask) == (networkAddress & mask);
    }

    private long parseIpv4(String ipAddress) {
        String[] parts = ipAddress.split("\\.", -1);
        if (parts.length != 4) {
            throw unauthorized(ClientCredentialFailureReason.IP_POLICY_INVALID);
        }

        long value = 0L;
        for (String part : parts) {
            int octet = parseOctet(part);
            value = (value << 8) | octet;
        }
        return value;
    }

    private int parseOctet(String part) {
        try {
            if (!StringUtils.hasText(part)) {
                throw new NumberFormatException("blank octet");
            }
            int octet = Integer.parseInt(part);
            if (octet < 0 || octet > 255) {
                throw new NumberFormatException("octet out of range");
            }
            return octet;
        } catch (NumberFormatException exception) {
            throw unauthorized(ClientCredentialFailureReason.IP_POLICY_INVALID);
        }
    }

    private int parsePrefixLength(String prefixLength) {
        try {
            int parsedPrefixLength = Integer.parseInt(prefixLength);
            if (parsedPrefixLength < 0 || parsedPrefixLength > 32) {
                throw new NumberFormatException("prefix length out of range");
            }
            return parsedPrefixLength;
        } catch (NumberFormatException exception) {
            throw unauthorized(ClientCredentialFailureReason.IP_POLICY_INVALID);
        }
    }

    private ClientCredentialException unauthorized(ClientCredentialFailureReason failureReason) {
        return new ClientCredentialException(
                responseCodeMapper.resolvePublicMessage(ClientCredentialException.UNAUTHORIZED_RESPONSE_CODE),
                failureReason);
    }
}
