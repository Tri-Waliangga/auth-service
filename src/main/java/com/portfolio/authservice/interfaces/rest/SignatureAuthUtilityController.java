package com.portfolio.authservice.interfaces.rest;

import com.portfolio.authservice.application.utility.SignatureAuthGenerationService;
import com.portfolio.authservice.interfaces.rest.dto.SnapErrorResponse;
import com.portfolio.authservice.interfaces.rest.dto.SignatureAuthGenerateRequest;
import com.portfolio.authservice.interfaces.rest.dto.SignatureAuthGenerateResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Profile({"dev", "local"})
@Tag(name = "Dev Utility", description = "Local/dev-only helpers. Never use production keys.")
public class SignatureAuthUtilityController {

    private final SignatureAuthGenerationService generationService;

    public SignatureAuthUtilityController(SignatureAuthGenerationService generationService) {
        this.generationService = generationService;
    }

    @Operation(
            summary = "[Dev/local only] Generate Access Token B2B Signature",
            description = """
                    WARNING: local/dev utility only. Do not enable this endpoint in production and never
                    submit production private keys. Generates SHA256withRSA signature for clientId|timestamp.
                    SNAP validation errors include 4007301 and 4007302.
                    """,
            parameters = {
                    @Parameter(name = "X-TIMESTAMP", in = ParameterIn.HEADER, required = false,
                            example = "2026-05-11T16:00:00Z"),
                    @Parameter(name = "X-CLIENT-KEY", in = ParameterIn.HEADER, required = false,
                            example = "962489e9-de5d-4eb7-92a4-b07d44d64bf4")
            })
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Generated local/dev signature",
                    content = @Content(schema = @Schema(implementation = SignatureAuthGenerateResponse.class),
                            examples = @ExampleObject(value = """
                                    {
                                      "signature": "base64-rsa-signature",
                                      "stringToSign": "962489e9-de5d-4eb7-92a4-b07d44d64bf4|2026-05-11T16:00:00Z",
                                      "algorithm": "SHA256withRSA",
                                      "additionalInfo": {}
                                    }
                                    """))),
            @ApiResponse(responseCode = "400", description = "SNAP 4007301 / 4007302",
                    content = @Content(schema = @Schema(implementation = SnapErrorResponse.class)))
    })
    @PostMapping(path = "/cashup/v1.0/utilities/signature-auth", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<SignatureAuthGenerateResponse> generateSignature(
            @RequestHeader(value = "X-CLIENT-KEY", required = false) String clientIdHeader,
            @RequestHeader(value = "X-TIMESTAMP", required = false) String timestampHeader,
            @io.swagger.v3.oas.annotations.parameters.RequestBody(required = true,
                    content = @Content(schema = @Schema(implementation = SignatureAuthGenerateRequest.class),
                            examples = @ExampleObject(value = """
                                    {
                                      "clientId": "962489e9-de5d-4eb7-92a4-b07d44d64bf4",
                                      "timestamp": "2026-05-11T16:00:00Z",
                                      "privateKeyPem": "-----BEGIN PRIVATE KEY-----\\nFAKE_LOCAL_TEST_KEY\\n-----END PRIVATE KEY-----"
                                    }
                                    """)))
            @RequestBody(required = false) SignatureAuthGenerateRequest request) {
        String clientId = resolveValue(request == null ? null : request.clientId(), clientIdHeader);
        String timestamp = resolveValue(request == null ? null : request.timestamp(), timestampHeader);
        String privateKeyPem = request == null ? null : request.privateKeyPem();

        return ResponseEntity.ok(generationService.generate(clientId, timestamp, privateKeyPem));
    }

    private String resolveValue(String bodyValue, String headerValue) {
        if (StringUtils.hasText(bodyValue)) {
            return bodyValue;
        }
        return headerValue;
    }
}
