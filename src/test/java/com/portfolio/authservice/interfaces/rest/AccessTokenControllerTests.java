package com.portfolio.authservice.interfaces.rest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.portfolio.authservice.application.command.TokenCommand;
import com.portfolio.authservice.application.token.TokenApplicationService;
import com.portfolio.authservice.common.error.SignatureVerificationException;
import com.portfolio.authservice.common.error.SnapValidationException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.common.response.SnapResponseMapper;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import com.portfolio.authservice.interfaces.rest.dto.AccessTokenB2BResponse;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class AccessTokenControllerTests {

    private TokenApplicationService tokenApplicationService;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        tokenApplicationService = mock(TokenApplicationService.class);
        SnapResponseCodeMapper responseCodeMapper = responseCodeMapper();
        mockMvc = MockMvcBuilders
                .standaloneSetup(new AccessTokenController(tokenApplicationService))
                .setControllerAdvice(new GlobalExceptionHandler(new SnapResponseMapper(responseCodeMapper)))
                .build();
    }

    @Test
    void validRequestReturnsSuccessResponse() throws Exception {
        when(tokenApplicationService.issueB2BToken(any(TokenCommand.class), eq(MediaType.APPLICATION_JSON_VALUE)))
                .thenReturn(new AccessTokenB2BResponse(
                        "2007300",
                        "Successful",
                        "jwt-token",
                        "Bearer",
                        "900",
                        Map.of()));

        mockMvc.perform(post("/cashup/v1.0/access-token/b2b")
                        .requestAttr(RequestCorrelationFilter.REQUEST_ID_ATTRIBUTE, "request-id-123")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-TIMESTAMP", "2026-04-30T10:00:00+07:00")
                        .header("X-CLIENT-KEY", "sample-client-id")
                        .header("X-SIGNATURE", "base64-signature")
                        .content("""
                                {
                                  "grantType": "client_credentials",
                                  "additionalInfo": {}
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(header().string("X-TIMESTAMP", "2026-04-30T10:00:00+07:00"))
                .andExpect(header().string("X-CLIENT-KEY", "sample-client-id"))
                .andExpect(jsonPath("$.responseCode").value("2007300"))
                .andExpect(jsonPath("$.accessToken").value("jwt-token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value("900"));

        ArgumentCaptor<TokenCommand> commandCaptor = ArgumentCaptor.forClass(TokenCommand.class);
        verify(tokenApplicationService).issueB2BToken(commandCaptor.capture(), eq(MediaType.APPLICATION_JSON_VALUE));
        assertThat(commandCaptor.getValue().requestId()).isEqualTo("request-id-123");
        verifyNoMoreInteractions(tokenApplicationService);
    }

    @Test
    void missingMandatoryFieldReturnsSnapBadRequest() throws Exception {
        when(tokenApplicationService.issueB2BToken(any(TokenCommand.class), eq(MediaType.APPLICATION_JSON_VALUE)))
                .thenThrow(new SnapValidationException(
                        "4007302",
                        "Invalid Mandatory Field X-CLIENT-KEY",
                        "Invalid mandatory field: X-CLIENT-KEY"));

        mockMvc.perform(post("/cashup/v1.0/access-token/b2b")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-TIMESTAMP", "2026-04-30T10:00:00+07:00")
                        .header("X-SIGNATURE", "base64-signature")
                        .content("""
                                {
                                  "grantType": "client_credentials",
                                  "additionalInfo": {}
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseCode").value("4007302"));
    }

    @Test
    void missingSignatureHeaderReturnsSnapBadRequest() throws Exception {
        when(tokenApplicationService.issueB2BToken(any(TokenCommand.class), eq(MediaType.APPLICATION_JSON_VALUE)))
                .thenThrow(new SnapValidationException(
                        "4007302",
                        "Invalid Mandatory Field X-SIGNATURE",
                        "Invalid mandatory field: X-SIGNATURE"));

        mockMvc.perform(post("/cashup/v1.0/access-token/b2b")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-TIMESTAMP", "2026-04-30T10:00:00+07:00")
                        .header("X-CLIENT-KEY", "sample-client-id")
                        .content("""
                                {
                                  "grantType": "client_credentials",
                                  "additionalInfo": {}
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseCode").value("4007302"))
                .andExpect(jsonPath("$.responseMessage").value("Invalid Mandatory Field X-SIGNATURE"));
    }

    @Test
    void malformedJsonReturnsSnapBadRequestOnAccessTokenEndpoint() throws Exception {
        mockMvc.perform(post("/cashup/v1.0/access-token/b2b")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-TIMESTAMP", "2026-04-30T10:00:00+07:00")
                        .header("X-CLIENT-KEY", "sample-client-id")
                        .header("X-SIGNATURE", "base64-signature")
                        .content("{bad-json"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseCode").value("4007302"))
                .andExpect(jsonPath("$.responseMessage").exists())
                .andExpect(jsonPath("$.timestamp").doesNotExist())
                .andExpect(jsonPath("$.error").doesNotExist())
                .andExpect(jsonPath("$.path").doesNotExist())
                .andExpect(jsonPath("$.trace").doesNotExist())
                .andExpect(jsonPath("$.message").doesNotExist());
    }

    @Test
    void invalidSignatureReturnsUnauthorized() throws Exception {
        when(tokenApplicationService.issueB2BToken(any(TokenCommand.class), eq(MediaType.APPLICATION_JSON_VALUE)))
                .thenThrow(new SignatureVerificationException("Unauthorized", "INVALID_SIGNATURE"));

        mockMvc.perform(post("/cashup/v1.0/access-token/b2b")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-TIMESTAMP", "2026-04-30T10:00:00+07:00")
                        .header("X-CLIENT-KEY", "sample-client-id")
                        .header("X-SIGNATURE", "invalid")
                        .content("""
                                {
                                  "grantType": "client_credentials",
                                  "additionalInfo": {}
                                }
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.responseCode").value("4017300"));
    }

    @Test
    void unexpectedErrorReturnsGeneralError() throws Exception {
        when(tokenApplicationService.issueB2BToken(any(TokenCommand.class), eq(MediaType.APPLICATION_JSON_VALUE)))
                .thenThrow(new RuntimeException("unexpected"));

        mockMvc.perform(post("/cashup/v1.0/access-token/b2b")
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-TIMESTAMP", "2026-04-30T10:00:00+07:00")
                        .header("X-CLIENT-KEY", "sample-client-id")
                        .header("X-SIGNATURE", "base64-signature")
                        .content("""
                                {
                                  "grantType": "client_credentials",
                                  "additionalInfo": {}
                                }
                                """))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.responseCode").value("5007300"));
    }

    @SuppressWarnings("unchecked")
    private SnapResponseCodeMapper responseCodeMapper() {
        ObjectProvider<ResponseCodeMappingJpaRepository> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        return new SnapResponseCodeMapper(provider);
    }
}
