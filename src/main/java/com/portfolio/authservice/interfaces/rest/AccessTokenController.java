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
import com.portfolio.authservice.interfaces.rest.dto.SnapErrorResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Tag(name = "Auth", description = "SNAP B2B authentication endpoints")
public class AccessTokenController {

    private final TokenApplicationService tokenApplicationService;

    public AccessTokenController(TokenApplicationService tokenApplicationService) {
        this.tokenApplicationService = tokenApplicationService;
    }

    @Operation(
            summary = "Access Token B2B",
            description = """
                    Issues a SNAP B2B access token. The auth signature is SHA256withRSA over
                    client_ID|X-TIMESTAMP. SNAP response codes: 2007300, 4007300, 4007301,
                    4007302, 4017300, 4037300, 5007300.
                    """,
            parameters = {
                    @Parameter(name = "X-TIMESTAMP", in = ParameterIn.HEADER, required = true,
                            example = "2026-05-11T16:00:00Z"),
                    @Parameter(name = "X-CLIENT-KEY", in = ParameterIn.HEADER, required = true,
                            example = "962489e9-de5d-4eb7-92a4-b07d44d64bf4"),
                    @Parameter(name = "X-SIGNATURE", in = ParameterIn.HEADER, required = true,
                            example = "base64-rsa-signature")
            })
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Successful - SNAP 2007300",
                    content = @Content(schema = @Schema(implementation = AccessTokenB2BResponse.class),
                            examples = @ExampleObject(value = """
                                    {
                                      "responseCode": "2007300",
                                      "responseMessage": "Successful",
                                      "accessToken": "eyJhbGciOiJSUzI1NiJ9.fake-token",
                                      "tokenType": "Bearer",
                                      "expiresIn": "900",
                                      "additionalInfo": {}
                                    }
                                    """))),
            @ApiResponse(responseCode = "400", description = "SNAP 4007300 / 4007301 / 4007302",
                    content = @Content(schema = @Schema(implementation = SnapErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "SNAP 4017300 Unauthorized",
                    content = @Content(schema = @Schema(implementation = SnapErrorResponse.class))),
            @ApiResponse(responseCode = "403", description = "SNAP 4037300 Forbidden",
                    content = @Content(schema = @Schema(implementation = SnapErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "SNAP 5007300 General Error",
                    content = @Content(schema = @Schema(implementation = SnapErrorResponse.class)))
    })
    @PostMapping(path = "/cashup/v1.0/access-token/b2b", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<AccessTokenB2BResponse> issueB2BToken(
            @RequestHeader(value = HttpHeaders.CONTENT_TYPE, required = false) String contentType,
            @RequestHeader(value = "X-TIMESTAMP", required = false) String timestamp,
            @RequestHeader(value = "X-CLIENT-KEY", required = false) String clientId,
            @RequestHeader(value = "X-SIGNATURE", required = false) String signature,
            @RequestHeader(value = HttpHeaders.USER_AGENT, required = false) String userAgent,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(required = true,
                    content = @Content(schema = @Schema(implementation = AccessTokenB2BRequest.class),
                            examples = @ExampleObject(value = """
                                    {
                                      "grantType": "client_credentials",
                                      "additionalInfo": {}
                                    }
                                    """)))
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
