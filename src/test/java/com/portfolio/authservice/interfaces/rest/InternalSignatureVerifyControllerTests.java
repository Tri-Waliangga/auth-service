package com.portfolio.authservice.interfaces.rest;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.portfolio.authservice.application.signature.InternalSignatureVerificationService;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.common.response.SnapResponseMapper;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import com.portfolio.authservice.interfaces.rest.dto.InternalSignatureVerifyRequest;
import com.portfolio.authservice.interfaces.rest.dto.InternalSignatureVerifyResponse;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class InternalSignatureVerifyControllerTests {

    private InternalSignatureVerificationService verificationService;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        verificationService = mock(InternalSignatureVerificationService.class);
        SnapResponseCodeMapper responseCodeMapper = responseCodeMapper();
        mockMvc = MockMvcBuilders
                .standaloneSetup(new InternalSignatureVerifyController(verificationService))
                .setControllerAdvice(new GlobalExceptionHandler(new SnapResponseMapper(responseCodeMapper)))
                .build();
    }

    @Test
    void validRequestReturnsVerificationResponse() throws Exception {
        when(verificationService.verify(any(InternalSignatureVerifyRequest.class), eq("10.10.10.10"), eq("JUnit"), eq("request-id-123")))
                .thenReturn(new InternalSignatureVerifyResponse(
                        true,
                        "2007300",
                        "Successful",
                        null,
                        Map.of("keyId", "key-1")));

        mockMvc.perform(post("/internal/v1.0/signatures/verify")
                        .requestAttr(RequestCorrelationFilter.REQUEST_ID_ATTRIBUTE, "request-id-123")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-Forwarded-For", "10.10.10.10")
                        .header("User-Agent", "JUnit")
                        .content("""
                                {
                                  "clientId": "client-id",
                                  "timestamp": "2026-05-07T15:00:00+07:00",
                                  "signature": "signature",
                                  "stringToSign": "custom-string-to-sign"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.responseCode").value("2007300"))
                .andExpect(jsonPath("$.responseMessage").value("Successful"))
                .andExpect(jsonPath("$.additionalInfo.keyId").value("key-1"));

        ArgumentCaptor<InternalSignatureVerifyRequest> requestCaptor =
                ArgumentCaptor.forClass(InternalSignatureVerifyRequest.class);
        verify(verificationService).verify(requestCaptor.capture(), eq("10.10.10.10"), eq("JUnit"), eq("request-id-123"));
        InternalSignatureVerifyRequest capturedRequest = requestCaptor.getValue();
        org.assertj.core.api.Assertions.assertThat(capturedRequest.clientId()).isEqualTo("client-id");
        org.assertj.core.api.Assertions.assertThat(capturedRequest.stringToSign()).isEqualTo("custom-string-to-sign");
    }

    @Test
    void missingMandatoryFieldReturnsSnapBadRequest() throws Exception {
        mockMvc.perform(post("/internal/v1.0/signatures/verify")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "clientId": "client-id",
                                  "timestamp": "2026-05-07T15:00:00+07:00"
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseCode").value("4007302"));
    }

    @SuppressWarnings("unchecked")
    private SnapResponseCodeMapper responseCodeMapper() {
        ObjectProvider<ResponseCodeMappingJpaRepository> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        return new SnapResponseCodeMapper(provider);
    }
}
