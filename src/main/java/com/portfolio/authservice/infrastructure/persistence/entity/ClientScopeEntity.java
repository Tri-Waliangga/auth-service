package com.portfolio.authservice.infrastructure.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "client_scopes")
public class ClientScopeEntity extends BaseAuditEntity {

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "api_client_id", nullable = false)
    private ApiClientEntity apiClient;

    @Column(name = "scope_code", nullable = false, length = 100)
    private String scopeCode;

    @Column(name = "service_code", nullable = false, length = 10)
    private String serviceCode;

    @Column(name = "is_active", nullable = false)
    private boolean active = true;

    public ApiClientEntity getApiClient() {
        return apiClient;
    }

    public void setApiClient(ApiClientEntity apiClient) {
        this.apiClient = apiClient;
    }

    public String getScopeCode() {
        return scopeCode;
    }

    public void setScopeCode(String scopeCode) {
        this.scopeCode = scopeCode;
    }

    public String getServiceCode() {
        return serviceCode;
    }

    public void setServiceCode(String serviceCode) {
        this.serviceCode = serviceCode;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }
}
