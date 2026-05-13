package com.portfolio.authservice.interfaces.rest;

import com.portfolio.authservice.application.signature.InternalSignatureVerificationService;
import com.portfolio.authservice.config.OpenApiConfig;
import com.portfolio.authservice.interfaces.rest.dto.InternalSignatureVerifyRequest;
import com.portfolio.authservice.interfaces.rest.dto.InternalSignatureVerifyResponse;
import com.portfolio.authservice.interfaces.rest.dto.SnapErrorResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.UUID;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Tag(name = "Internal", description = "Internal endpoints protected by X-INTERNAL-API-KEY")
public class InternalSignatureVerifyController {

    private final InternalSignatureVerificationService verificationService;

    public InternalSignatureVerifyController(InternalSignatureVerificationService verificationService) {
        this.verificationService = verificationService;
    }

    @Operation(
            summary = "[Internal] Verify SNAP Signature",
            description = """
                    Verifies SHA256withRSA signature material against the active client public key.
                    Requires X-INTERNAL-API-KEY. SNAP response codes: 2007300, 4007302, 4017300, 5007300.
                    """,
            security = @SecurityRequirement(name = OpenApiConfig.INTERNAL_API_KEY_SCHEME))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Signature verification result",
                    content = @Content(schema = @Schema(implementation = InternalSignatureVerifyResponse.class),
                            examples = @ExampleObject(value = """
                                    {
                                      "valid": true,
                                      "responseCode": "2007300",
                                      "responseMessage": "Successful",
                                      "failureReason": null,
                                      "additionalInfo": {}
                                    }
                                    """))),
            @ApiResponse(responseCode = "400", description = "SNAP 4007302 Invalid Mandatory Field",
                    content = @Content(schema = @Schema(implementation = SnapErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "SNAP 4017300 Unauthorized",
                    content = @Content(schema = @Schema(implementation = SnapErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "SNAP 5007300 General Error",
                    content = @Content(schema = @Schema(implementation = SnapErrorResponse.class)))
    })
    @PostMapping(path = "/internal/v1.0/signatures/verify", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<InternalSignatureVerifyResponse> verify(
            @RequestHeader(value = HttpHeaders.USER_AGENT, required = false) String userAgent,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(required = true,
                    content = @Content(schema = @Schema(implementation = InternalSignatureVerifyRequest.class),
                            examples = @ExampleObject(value = """
                                    {
                                      "clientId": "962489e9-de5d-4eb7-92a4-b07d44d64bf4",
                                      "timestamp": "2026-05-11T16:00:00Z",
                                      "signature": "base64-rsa-signature",
                                      "stringToSign": "962489e9-de5d-4eb7-92a4-b07d44d64bf4|2026-05-11T16:00:00Z"
                                    }
                                    """)))
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
