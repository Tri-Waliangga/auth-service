package com.portfolio.authservice.interfaces.rest;

import com.portfolio.authservice.application.token.TokenIntrospectionService;
import com.portfolio.authservice.config.OpenApiConfig;
import com.portfolio.authservice.interfaces.rest.dto.SnapErrorResponse;
import com.portfolio.authservice.interfaces.rest.dto.TokenIntrospectionRequest;
import com.portfolio.authservice.interfaces.rest.dto.TokenIntrospectionResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Tag(name = "Internal", description = "Internal endpoints protected by X-INTERNAL-API-KEY")
public class TokenIntrospectionController {

    private final TokenIntrospectionService tokenIntrospectionService;

    public TokenIntrospectionController(TokenIntrospectionService tokenIntrospectionService) {
        this.tokenIntrospectionService = tokenIntrospectionService;
    }

    @Operation(
            summary = "[Internal] Token Introspection",
            description = """
                    Validates an issued access token for internal callers. Requires X-INTERNAL-API-KEY.
                    Malformed or unknown tokens return active=false; expired tokens use SNAP 4017301.
                    SNAP response codes: 4007302, 4017301, 5007300.
                    """,
            security = @SecurityRequirement(name = OpenApiConfig.INTERNAL_API_KEY_SCHEME))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Token introspection result",
                    content = @Content(schema = @Schema(implementation = TokenIntrospectionResponse.class),
                            examples = @ExampleObject(value = """
                                    {
                                      "active": true,
                                      "clientId": "962489e9-de5d-4eb7-92a4-b07d44d64bf4",
                                      "scope": "openid snap:auth:token",
                                      "tokenType": "Bearer",
                                      "expiresAt": "2026-05-11T16:15:00Z",
                                      "issuedAt": "2026-05-11T16:00:00Z",
                                      "subject": "962489e9-de5d-4eb7-92a4-b07d44d64bf4",
                                      "additionalInfo": { "jti": "00000000-0000-4000-8000-000000000000" }
                                    }
                                    """))),
            @ApiResponse(responseCode = "400", description = "SNAP 4007302 Invalid Mandatory Field",
                    content = @Content(schema = @Schema(implementation = SnapErrorResponse.class))),
            @ApiResponse(responseCode = "401", description = "SNAP 4017301 Invalid Token (B2B)",
                    content = @Content(schema = @Schema(implementation = SnapErrorResponse.class))),
            @ApiResponse(responseCode = "500", description = "SNAP 5007300 General Error",
                    content = @Content(schema = @Schema(implementation = SnapErrorResponse.class)))
    })
    @PostMapping(path = "/internal/v1.0/tokens/introspect", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TokenIntrospectionResponse> introspect(
            @io.swagger.v3.oas.annotations.parameters.RequestBody(required = true,
                    content = @Content(schema = @Schema(implementation = TokenIntrospectionRequest.class),
                            examples = @ExampleObject(value = """
                                    {
                                      "token": "eyJhbGciOiJSUzI1NiJ9.fake-token"
                                    }
                                    """)))
            @Valid @RequestBody TokenIntrospectionRequest request) {
        return ResponseEntity.ok(tokenIntrospectionService.introspect(request.token()));
    }
}
