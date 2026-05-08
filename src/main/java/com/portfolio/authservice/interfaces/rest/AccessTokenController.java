package com.portfolio.authservice.interfaces.rest;

import com.portfolio.authservice.application.command.TokenCommand;
import com.portfolio.authservice.application.token.TokenApplicationService;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiAuditLogJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiClientJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ClientPublicKeyJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ClientScopeJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.OauthAccessTokenJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.SignatureAuditLogJpaRepository;
import com.portfolio.authservice.interfaces.rest.dto.AccessTokenB2BRequest;
import com.portfolio.authservice.interfaces.rest.dto.AccessTokenB2BResponse;
import jakarta.servlet.http.HttpServletRequest;
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
        ClientScopeJpaRepository.class,
        OauthAccessTokenJpaRepository.class,
        SignatureAuditLogJpaRepository.class
})
public class AccessTokenController {

    private final TokenApplicationService tokenApplicationService;

    public AccessTokenController(TokenApplicationService tokenApplicationService) {
        this.tokenApplicationService = tokenApplicationService;
    }

    @PostMapping(path = "/cashup/v1.0/access-token/b2b", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AccessTokenB2BResponse> issueB2BToken(
            @RequestHeader(value = HttpHeaders.CONTENT_TYPE, required = false) String contentType,
            @RequestHeader(value = "X-TIMESTAMP", required = false) String timestamp,
            @RequestHeader(value = "X-CLIENT-KEY", required = false) String clientId,
            @RequestHeader(value = "X-SIGNATURE", required = false) String signature,
            @RequestHeader(value = HttpHeaders.USER_AGENT, required = false) String userAgent,
            @RequestBody(required = false) AccessTokenB2BRequest request,
            HttpServletRequest servletRequest) {
        TokenCommand command = new TokenCommand(
                clientId,
                timestamp,
                signature,
                request == null ? null : request.grantType(),
                remoteIp(servletRequest),
                userAgent,
                requestId(servletRequest));
        AccessTokenB2BResponse response = tokenApplicationService.issueB2BToken(command, contentType);
        return ResponseEntity.ok()
                .header("X-TIMESTAMP", timestamp)
                .header("X-CLIENT-KEY", clientId)
                .body(response);
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
