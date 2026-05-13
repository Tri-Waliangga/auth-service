package com.portfolio.authservice.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.portfolio.authservice.support.PersistenceBackedServiceMocks;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "spring.autoconfigure.exclude=org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration,"
                        + "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration,"
                        + "org.springframework.boot.autoconfigure.flyway.FlywayAutoConfiguration",
                "auth.internal.api-key=test-internal-key"
        })
class OpenApiDocumentationTests extends PersistenceBackedServiceMocks {

    private final TestRestTemplate restTemplate = new TestRestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @LocalServerPort
    private int port;

    @Test
    void swaggerUiIsPubliclyAccessible() {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "http://localhost:" + port + "/swagger-ui.html",
                String.class);

        assertThat(response.getStatusCode()).isNotIn(HttpStatus.UNAUTHORIZED, HttpStatus.FORBIDDEN);
    }

    @Test
    void apiDocsContainMainEndpointsSnapCodesAndLabels() throws Exception {
        ResponseEntity<String> response = restTemplate.getForEntity(
                "http://localhost:" + port + "/v3/api-docs",
                String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotBlank();

        JsonNode document = objectMapper.readTree(response.getBody());
        JsonNode paths = document.path("paths");

        assertThat(paths.has("/cashup/v1.0/access-token/b2b")).isTrue();
        assertThat(paths.has("/internal/v1.0/tokens/introspect")).isTrue();
        assertThat(paths.has("/internal/v1.0/signatures/verify")).isTrue();
        assertThat(paths.has("/cashup/v1.0/utilities/signature-auth")).isTrue();
        assertThat(paths.has("/actuator/health")).isTrue();

        assertThat(response.getBody()).contains(
                "2007300",
                "4007300",
                "4007301",
                "4007302",
                "4017300",
                "4017301",
                "4037300",
                "5007300");
        assertThat(response.getBody()).contains("Auth", "Internal", "Dev Utility", "Operations");
        assertThat(response.getBody()).contains("local/dev utility only", "Do not enable", "production private keys");

        JsonNode internalSecurityScheme = document.at("/components/securitySchemes/internalApiKey");
        assertThat(internalSecurityScheme.path("type").asText()).isEqualTo("apiKey");
        assertThat(internalSecurityScheme.path("in").asText()).isEqualTo("header");
        assertThat(internalSecurityScheme.path("name").asText()).isEqualTo("X-INTERNAL-API-KEY");

        assertThat(paths.path("/internal/v1.0/tokens/introspect").path("post").path("security").toString())
                .contains(OpenApiConfig.INTERNAL_API_KEY_SCHEME);
        assertThat(paths.path("/internal/v1.0/signatures/verify").path("post").path("security").toString())
                .contains(OpenApiConfig.INTERNAL_API_KEY_SCHEME);
    }
}
