package com.portfolio.authservice.interfaces.rest;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.portfolio.authservice.application.utility.SignatureAuthGenerationService;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.common.response.SnapResponseMapper;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SignatureAuthUtilityControllerTests {

    private MockMvc mockMvc;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        SnapResponseCodeMapper responseCodeMapper = responseCodeMapper();
        SignatureAuthGenerationService generationService = new SignatureAuthGenerationService(responseCodeMapper);
        mockMvc = MockMvcBuilders
                .standaloneSetup(new SignatureAuthUtilityController(generationService))
                .setControllerAdvice(new GlobalExceptionHandler(new SnapResponseMapper(responseCodeMapper)))
                .build();

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();
    }

    @Test
    void bodyFieldsGenerateSignatureResponse() throws Exception {
        mockMvc.perform(post("/cashup/v1.0/utilities/signature-auth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "clientId": "client-id",
                                  "timestamp": "2026-05-10T12:00:00+07:00",
                                  "privateKeyPem": "%s"
                                }
                                """.formatted(toEscapedPrivateKeyPem(keyPair.getPrivate()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.signature").isNotEmpty())
                .andExpect(jsonPath("$.stringToSign").value("client-id|2026-05-10T12:00:00+07:00"))
                .andExpect(jsonPath("$.algorithm").value("SHA256withRSA"))
                .andExpect(jsonPath("$.additionalInfo.developmentOnly").value(true));
    }

    @Test
    void headersCanProvideClientIdAndTimestampForPostmanCompatibility() throws Exception {
        mockMvc.perform(post("/cashup/v1.0/utilities/signature-auth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-CLIENT-KEY", "client-id")
                        .header("X-TIMESTAMP", "2026-05-10T12:00:00+07:00")
                        .content("""
                                {
                                  "privateKeyPem": "%s"
                                }
                                """.formatted(toEscapedPrivateKeyPem(keyPair.getPrivate()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.signature").isNotEmpty())
                .andExpect(jsonPath("$.stringToSign").value("client-id|2026-05-10T12:00:00+07:00"));
    }

    @Test
    void missingMandatoryFieldReturnsSnapBadRequest() throws Exception {
        mockMvc.perform(post("/cashup/v1.0/utilities/signature-auth")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "clientId": "client-id",
                                  "privateKeyPem": "%s"
                                }
                                """.formatted(toEscapedPrivateKeyPem(keyPair.getPrivate()))))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseCode").value("4007302"));
    }

    private String toEscapedPrivateKeyPem(PrivateKey privateKey) {
        return toPrivateKeyPem(privateKey).replace("\n", "\\n");
    }

    private String toPrivateKeyPem(PrivateKey privateKey) {
        String encodedKey = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(privateKey.getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + encodedKey + "\n-----END PRIVATE KEY-----";
    }

    @SuppressWarnings("unchecked")
    private SnapResponseCodeMapper responseCodeMapper() {
        ObjectProvider<ResponseCodeMappingJpaRepository> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        return new SnapResponseCodeMapper(provider);
    }
}
