package com.portfolio.authservice.infrastructure.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "signature_audit_logs")
public class SignatureAuditLogEntity extends BaseAuditEntity {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "api_client_id")
    private ApiClientEntity apiClient;

    @Column(name = "request_id", nullable = false, length = 64)
    private String requestId;

    @Column(name = "signature_type", nullable = false, length = 30)
    private String signatureType;

    @Column(name = "algorithm", nullable = false, length = 32)
    private String algorithm;

    @Column(name = "string_to_sign_hash", nullable = false, length = 128)
    private String stringToSignHash;

    @Column(name = "validation_result", nullable = false, length = 20)
    private String validationResult;

    @Column(name = "failure_reason", length = 255)
    private String failureReason;

    @Column(name = "remote_ip", length = 64)
    private String remoteIp;

    @Column(name = "user_agent", length = 500)
    private String userAgent;

    public ApiClientEntity getApiClient() {
        return apiClient;
    }

    public void setApiClient(ApiClientEntity apiClient) {
        this.apiClient = apiClient;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public String getSignatureType() {
        return signatureType;
    }

    public void setSignatureType(String signatureType) {
        this.signatureType = signatureType;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getStringToSignHash() {
        return stringToSignHash;
    }

    public void setStringToSignHash(String stringToSignHash) {
        this.stringToSignHash = stringToSignHash;
    }

    public String getValidationResult() {
        return validationResult;
    }

    public void setValidationResult(String validationResult) {
        this.validationResult = validationResult;
    }

    public String getFailureReason() {
        return failureReason;
    }

    public void setFailureReason(String failureReason) {
        this.failureReason = failureReason;
    }

    public String getRemoteIp() {
        return remoteIp;
    }

    public void setRemoteIp(String remoteIp) {
        this.remoteIp = remoteIp;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }
}
