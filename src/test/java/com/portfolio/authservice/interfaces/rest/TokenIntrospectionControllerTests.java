package com.portfolio.authservice.interfaces.rest;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.portfolio.authservice.application.token.TokenIntrospectionService;
import com.portfolio.authservice.common.error.SnapUnauthorizedException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.common.response.SnapResponseMapper;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import com.portfolio.authservice.interfaces.rest.dto.TokenIntrospectionResponse;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class TokenIntrospectionControllerTests {

    private TokenIntrospectionService tokenIntrospectionService;
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        tokenIntrospectionService = mock(TokenIntrospectionService.class);
        SnapResponseCodeMapper responseCodeMapper = responseCodeMapper();
        mockMvc = MockMvcBuilders
                .standaloneSetup(new TokenIntrospectionController(tokenIntrospectionService))
                .setControllerAdvice(new GlobalExceptionHandler(new SnapResponseMapper(responseCodeMapper)))
                .build();
    }

    @Test
    void validRequestReturnsIntrospectionResponse() throws Exception {
        when(tokenIntrospectionService.introspect(eq("jwt-token")))
                .thenReturn(new TokenIntrospectionResponse(
                        true,
                        "client-id",
                        "openid snap:auth:token",
                        "Bearer",
                        Instant.parse("2026-05-07T08:15:00Z"),
                        Instant.parse("2026-05-07T08:00:00Z"),
                        "client-id",
                        Map.of("jti", "jti-1")));

        mockMvc.perform(post("/internal/v1.0/tokens/introspect")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "token": "jwt-token"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.clientId").value("client-id"))
                .andExpect(jsonPath("$.scope").value("openid snap:auth:token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.subject").value("client-id"))
                .andExpect(jsonPath("$.additionalInfo.jti").value("jti-1"));
    }

    @Test
    void blankTokenReturnsSnapBadRequest() throws Exception {
        mockMvc.perform(post("/internal/v1.0/tokens/introspect")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "token": " "
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseCode").value("4007302"));
    }

    @Test
    void expiredTokenReturnsInvalidTokenSnapError() throws Exception {
        when(tokenIntrospectionService.introspect(eq("expired-token")))
                .thenThrow(new SnapUnauthorizedException(
                        "4017301",
                        "Invalid Token (B2B)",
                        "TOKEN_EXPIRED"));

        mockMvc.perform(post("/internal/v1.0/tokens/introspect")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "token": "expired-token"
                                }
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.responseCode").value("4017301"))
                .andExpect(jsonPath("$.responseMessage").value("Invalid Token (B2B)"));
    }

    @SuppressWarnings("unchecked")
    private SnapResponseCodeMapper responseCodeMapper() {
        ObjectProvider<ResponseCodeMappingJpaRepository> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        return new SnapResponseCodeMapper(provider);
    }
}
