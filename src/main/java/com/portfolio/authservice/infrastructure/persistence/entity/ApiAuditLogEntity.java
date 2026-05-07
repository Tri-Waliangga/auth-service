package com.portfolio.authservice.infrastructure.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity
@Table(name = "api_audit_logs")
public class ApiAuditLogEntity extends BaseAuditEntity {

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "api_client_id")
    private ApiClientEntity apiClient;

    @Column(name = "request_id", nullable = false, length = 64)
    private String requestId;

    @Column(name = "endpoint_path", nullable = false, length = 255)
    private String endpointPath;

    @Column(name = "http_method", nullable = false, length = 10)
    private String httpMethod;

    @Column(name = "http_status", nullable = false)
    private Integer httpStatus;

    @Column(name = "response_code", length = 7)
    private String responseCode;

    @Column(name = "response_message", length = 150)
    private String responseMessage;

    @Column(name = "latency_ms")
    private Long latencyMs;

    @Column(name = "remote_ip", length = 64)
    private String remoteIp;

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

    public String getEndpointPath() {
        return endpointPath;
    }

    public void setEndpointPath(String endpointPath) {
        this.endpointPath = endpointPath;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public Integer getHttpStatus() {
        return httpStatus;
    }

    public void setHttpStatus(Integer httpStatus) {
        this.httpStatus = httpStatus;
    }

    public String getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(String responseCode) {
        this.responseCode = responseCode;
    }

    public String getResponseMessage() {
        return responseMessage;
    }

    public void setResponseMessage(String responseMessage) {
        this.responseMessage = responseMessage;
    }

    public Long getLatencyMs() {
        return latencyMs;
    }

    public void setLatencyMs(Long latencyMs) {
        this.latencyMs = latencyMs;
    }

    public String getRemoteIp() {
        return remoteIp;
    }

    public void setRemoteIp(String remoteIp) {
        this.remoteIp = remoteIp;
    }
}
