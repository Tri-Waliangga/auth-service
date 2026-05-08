package com.portfolio.authservice.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

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

    @Test
    void actuatorHealthIsPubliclyAccessible() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "http://localhost:" + port + "/actuator/health",
                String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("\"status\":\"UP\"");
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

        assertThat(response.getStatusCode()).isNotIn(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN);
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

    @TestConfiguration
    static class InternalTestControllerConfiguration {

        @RestController
        static class InternalTestController {

            @PostMapping("/internal/v1.0/tokens/introspect")
            Map<String, Object> introspect() {
                return Map.of("active", true);
            }
        }
    }
}
