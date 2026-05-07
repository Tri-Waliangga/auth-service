package com.portfolio.authservice.infrastructure.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;

@Entity
@Table(name = "oauth_auth_codes")
public class OauthAuthCodeEntity extends BaseAuditEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "api_client_id", nullable = false)
    private ApiClientEntity apiClient;

    @Column(name = "auth_code_hash", nullable = false, unique = true, length = 128)
    private String authCodeHash;

    @Column(name = "customer_reference", nullable = false, length = 150)
    private String customerReference;

    @Column(name = "redirect_uri", length = 500)
    private String redirectUri;

    @Column(name = "scopes", length = 500)
    private String scopes;

    @Column(name = "expires_at", nullable = false, columnDefinition = "TIMESTAMP")
    private Instant expiresAt;

    @Column(name = "used_at", columnDefinition = "TIMESTAMP")
    private Instant usedAt;

    public ApiClientEntity getApiClient() {
        return apiClient;
    }

    public void setApiClient(ApiClientEntity apiClient) {
        this.apiClient = apiClient;
    }

    public String getAuthCodeHash() {
        return authCodeHash;
    }

    public void setAuthCodeHash(String authCodeHash) {
        this.authCodeHash = authCodeHash;
    }

    public String getCustomerReference() {
        return customerReference;
    }

    public void setCustomerReference(String customerReference) {
        this.customerReference = customerReference;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getScopes() {
        return scopes;
    }

    public void setScopes(String scopes) {
        this.scopes = scopes;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Instant getUsedAt() {
        return usedAt;
    }

    public void setUsedAt(Instant usedAt) {
        this.usedAt = usedAt;
    }
}
