package com.portfolio.authservice.interfaces.rest;

import com.portfolio.authservice.application.utility.SignatureAuthGenerationService;
import com.portfolio.authservice.interfaces.rest.dto.SignatureAuthGenerateRequest;
import com.portfolio.authservice.interfaces.rest.dto.SignatureAuthGenerateResponse;
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
public class SignatureAuthUtilityController {

    private final SignatureAuthGenerationService generationService;

    public SignatureAuthUtilityController(SignatureAuthGenerationService generationService) {
        this.generationService = generationService;
    }

    @PostMapping(path = "/cashup/v1.0/utilities/signature-auth", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<SignatureAuthGenerateResponse> generateSignature(
            @RequestHeader(value = "X-CLIENT-KEY", required = false) String clientIdHeader,
            @RequestHeader(value = "X-TIMESTAMP", required = false) String timestampHeader,
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
