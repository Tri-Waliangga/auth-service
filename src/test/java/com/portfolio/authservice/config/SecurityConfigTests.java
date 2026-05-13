package com.portfolio.authservice.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import com.portfolio.authservice.application.audit.AuditService;
import com.portfolio.authservice.application.credential.ClientCredentialService;
import com.portfolio.authservice.application.signature.InternalSignatureVerificationService;
import com.portfolio.authservice.application.token.JwtTokenService;
import com.portfolio.authservice.application.token.TokenApplicationService;
import com.portfolio.authservice.application.token.TokenIntrospectionService;
import com.portfolio.authservice.application.token.TokenMetadataService;
import com.portfolio.authservice.interfaces.rest.dto.AccessTokenB2BResponse;
import com.portfolio.authservice.interfaces.rest.dto.TokenIntrospectionResponse;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration,"
                        + "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration,"
                        + "org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration",
                "auth.internal.api-key=test-internal-key"
        })
class SecurityConfigTests {

    @LocalServerPort
    private int port;

    private final TestRestTemplate restTemplate = new TestRestTemplate();

    @MockitoBean
    private AuditService auditService;

    @MockitoBean
    private ClientCredentialService clientCredentialService;

    @MockitoBean
    private InternalSignatureVerificationService internalSignatureVerificationService;

    @MockitoBean
    private JwtTokenService jwtTokenService;

    @MockitoBean
    private TokenApplicationService tokenApplicationService;

    @MockitoBean
    private TokenIntrospectionService tokenIntrospectionService;

    @MockitoBean
    private TokenMetadataService tokenMetadataService;

    @BeforeEach
    void setUpMocks() {
        when(tokenApplicationService.issueB2BToken(any(), any())).thenReturn(new AccessTokenB2BResponse(
                "2007300",
                "Successful",
                "test-access-token",
                "Bearer",
                "900",
                Map.of()));
        when(tokenIntrospectionService.introspect(anyString())).thenReturn(new TokenIntrospectionResponse(
                true,
                "test-client-id",
                "openid snap:auth:token",
                "Bearer",
                Instant.parse("2026-05-11T16:15:00Z"),
                Instant.parse("2026-05-11T16:00:00Z"),
                "test-client-id",
                Map.of("jti", "test-jti")));
    }

    @Test
    void actuatorHealthIsPubliclyAccessible() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "http://localhost:" + port + "/actuator/health",
                String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"status\":\"UP\"");
    }

    @Test
    void actuatorPrometheusIsNotBlockedBySecurity() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "http://localhost:" + port + "/actuator/prometheus",
                String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertNoBasicAuthenticateHeader(response);
        assertThat(response.getBody()).contains(
                "# HELP",
                "# TYPE",
                "auth_token_request_success_total",
                "auth_token_request_failure_total",
                "auth_token_invalid_signature_total",
                "auth_token_unauthorized_total",
                "auth_token_request_latency_seconds");
    }

    @Test
    void accessTokenEndpointIsPubliclyAccessible() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> request = new HttpEntity<>("{}", headers);

        ResponseEntity<String> response = restTemplate.postForEntity(
                "http://localhost:" + port + "/cashup/v1.0/access-token/b2b",
                request,
                String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertNoBasicAuthenticateHeader(response);
        assertThat(response.getBody()).contains("\"responseCode\":\"2007300\"");
    }

    @Test
    void internalEndpointRejectsMissingApiKey() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<String> request = new HttpEntity<>("{\"token\":\"jwt-token\"}", headers);

        ResponseEntity<String> response = restTemplate.postForEntity(
                "http://localhost:" + port + "/internal/v1.0/tokens/introspect",
                request,
                String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void internalEndpointRejectsWrongApiKey() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-INTERNAL-API-KEY", "wrong-key");
        HttpEntity<String> request = new HttpEntity<>("{\"token\":\"jwt-token\"}", headers);

        ResponseEntity<String> response = restTemplate.postForEntity(
                "http://localhost:" + port + "/internal/v1.0/tokens/introspect",
                request,
                String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void internalEndpointAllowsCorrectApiKey() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-INTERNAL-API-KEY", "test-internal-key");
        HttpEntity<String> request = new HttpEntity<>("{\"token\":\"jwt-token\"}", headers);

        ResponseEntity<String> response = restTemplate.postForEntity(
                "http://localhost:" + port + "/internal/v1.0/tokens/introspect",
                request,
                String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"active\":true");
    }

    @Test
    void unlistedEndpointIsNotPubliclyAccessible() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "http://localhost:" + port + "/cashup/v1.0/private",
                String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertNoBasicAuthenticateHeader(response);
    }

    private void assertNoBasicAuthenticateHeader(ResponseEntity<?> response) {
        List<String> authenticateHeaders = response.getHeaders().getOrEmpty(HttpHeaders.WWW_AUTHENTICATE);

        assertThat(authenticateHeaders).noneMatch(value -> value.contains("Basic"));
    }
}
