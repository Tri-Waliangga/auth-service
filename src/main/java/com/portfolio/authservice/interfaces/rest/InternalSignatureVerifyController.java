package com.portfolio.authservice.interfaces.rest;

import com.portfolio.authservice.application.signature.InternalSignatureVerificationService;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiAuditLogJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiClientJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ClientPublicKeyJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.SignatureAuditLogJpaRepository;
import com.portfolio.authservice.interfaces.rest.dto.InternalSignatureVerifyRequest;
import com.portfolio.authservice.interfaces.rest.dto.InternalSignatureVerifyResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
@ConditionalOnBean({
        ApiAuditLogJpaRepository.class,
        ApiClientJpaRepository.class,
        ClientPublicKeyJpaRepository.class,
        SignatureAuditLogJpaRepository.class,
        InternalSignatureVerificationService.class
})
public class InternalSignatureVerifyController {

    private final InternalSignatureVerificationService verificationService;

    public InternalSignatureVerifyController(InternalSignatureVerificationService verificationService) {
        this.verificationService = verificationService;
    }

    @PostMapping(path = "/internal/v1.0/signatures/verify", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<InternalSignatureVerifyResponse> verify(
            @RequestHeader(value = HttpHeaders.USER_AGENT, required = false) String userAgent,
            @Valid @RequestBody InternalSignatureVerifyRequest request,
            HttpServletRequest servletRequest) {
        return ResponseEntity.ok(verificationService.verify(
                request,
                remoteIp(servletRequest),
                userAgent,
                requestId(servletRequest)));
    }

    private String remoteIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",", 2)[0].trim();
        }
        return request.getRemoteAddr();
    }

    private String requestId(HttpServletRequest request) {
        Object requestId = request.getAttribute(RequestCorrelationFilter.REQUEST_ID_ATTRIBUTE);
        if (requestId instanceof String value && !value.isBlank()) {
            return value;
        }
        return UUID.randomUUID().toString();
    }
}
