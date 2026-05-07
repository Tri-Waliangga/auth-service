package com.portfolio.authservice.infrastructure.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

@Entity
@Table(name = "response_code_mappings")
public class ResponseCodeMappingEntity extends BaseAuditEntity {

    @Column(name = "category", nullable = false, length = 30)
    private String category;

    @Column(name = "http_status", nullable = false)
    private Integer httpStatus;

    @Column(name = "service_code", nullable = false, length = 10)
    private String serviceCode;

    @Column(name = "case_code", nullable = false, length = 2)
    private String caseCode;

    @Column(name = "response_code", nullable = false, unique = true, length = 7)
    private String responseCode;

    @Column(name = "response_message", nullable = false, length = 150)
    private String responseMessage;

    @Column(name = "description", length = 2000)
    private String description;

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public Integer getHttpStatus() {
        return httpStatus;
    }

    public void setHttpStatus(Integer httpStatus) {
        this.httpStatus = httpStatus;
    }

    public String getServiceCode() {
        return serviceCode;
    }

    public void setServiceCode(String serviceCode) {
        this.serviceCode = serviceCode;
    }

    public String getCaseCode() {
        return caseCode;
    }

    public void setCaseCode(String caseCode) {
        this.caseCode = caseCode;
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

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
}
