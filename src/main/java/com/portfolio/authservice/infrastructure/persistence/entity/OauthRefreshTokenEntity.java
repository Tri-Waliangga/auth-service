package com.portfolio.authservice.infrastructure.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "oauth_refresh_tokens")
public class OauthRefreshTokenEntity extends BaseAuditEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "api_client_id", nullable = false)
    private ApiClientEntity apiClient;

    @Column(name = "refresh_token_hash", nullable = false, unique = true, length = 128)
    private String refreshTokenHash;

    @Column(name = "customer_reference", nullable = false, length = 150)
    private String customerReference;

    @Column(name = "scopes", length = 500)
    private String scopes;

    @Column(name = "issued_at", nullable = false, columnDefinition = "TIMESTAMP")
    private Instant issuedAt;

    @Column(name = "expires_at", nullable = false, columnDefinition = "TIMESTAMP")
    private Instant expiresAt;

    @Column(name = "revoked_at", columnDefinition = "TIMESTAMP")
    private Instant revokedAt;

    public ApiClientEntity getApiClient() {
        return apiClient;
    }

    public void setApiClient(ApiClientEntity apiClient) {
        this.apiClient = apiClient;
    }

    public String getRefreshTokenHash() {
        return refreshTokenHash;
    }

    public void setRefreshTokenHash(String refreshTokenHash) {
        this.refreshTokenHash = refreshTokenHash;
    }

    public String getCustomerReference() {
        return customerReference;
    }

    public void setCustomerReference(String customerReference) {
        this.customerReference = customerReference;
    }

    public String getScopes() {
        return scopes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public Instant getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Instant issuedAt) {
        this.issuedAt = issuedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(Instant revokedAt) {
        this.revokedAt = revokedAt;
    }
}
