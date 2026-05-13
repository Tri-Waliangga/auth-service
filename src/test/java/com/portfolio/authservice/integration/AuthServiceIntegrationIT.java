package com.portfolio.authservice.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.portfolio.authservice.application.audit.AuditService;
import com.portfolio.authservice.application.credential.ClientCredentialService;
import com.portfolio.authservice.application.observability.TokenMetrics;
import com.portfolio.authservice.application.token.JwtTokenService;
import com.portfolio.authservice.application.token.TokenApplicationService;
import com.portfolio.authservice.application.token.TokenIntrospectionService;
import com.portfolio.authservice.application.token.TokenMetadataService;
import com.portfolio.authservice.application.validation.SnapRequestValidator;
import com.portfolio.authservice.common.response.SnapResponseMapper;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.config.JwtProperties;
import com.portfolio.authservice.domain.port.SignatureVerifier;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiAuditLogJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ApiClientJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ClientPublicKeyJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.ClientScopeJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.OauthAccessTokenJpaRepository;
import com.portfolio.authservice.infrastructure.persistence.repository.SignatureAuditLogJpaRepository;
import com.portfolio.authservice.interfaces.rest.AccessTokenController;
import com.portfolio.authservice.interfaces.rest.GlobalExceptionHandler;
import com.portfolio.authservice.interfaces.rest.RequestCorrelationFilter;
import com.portfolio.authservice.interfaces.rest.TokenIntrospectionController;
import com.portfolio.authservice.support.TestCryptoFixtures;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.testcontainers.containers.MySQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthServiceIntegrationIT {

    private static final String ACCESS_TOKEN_PATH = "/cashup/v1.0/access-token/b2b";
    private static final String INTROSPECTION_PATH = "/internal/v1.0/tokens/introspect";
    private static final String SEED_CLIENT_ID = "962489e9-de5d-4eb7-92a4-b07d44d64bf4";
    private static final String INTERNAL_API_KEY = "integration-test-internal-key";

    @Container
    private static final MySQLContainer<?> MYSQL = new MySQLContainer<>("mysql:8.4")
            .withDatabaseName("auth_db")
            .withUsername("auth_service")
            .withPassword("auth_service_password");

    private MockMvc mockMvc;

    @LocalServerPort
    private int port;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private TokenApplicationService tokenApplicationService;

    @Autowired
    private TokenIntrospectionService tokenIntrospectionService;

    @Autowired
    private SnapResponseMapper responseMapper;

    @Autowired
    private RequestCorrelationFilter requestCorrelationFilter;

    private final TestRestTemplate restTemplate = new TestRestTemplate();

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", MYSQL::getJdbcUrl);
        registry.add("spring.datasource.username", MYSQL::getUsername);
        registry.add("spring.datasource.password", MYSQL::getPassword);
        registry.add("spring.datasource.driver-class-name", MYSQL::getDriverClassName);
        registry.add("spring.flyway.enabled", () -> "true");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "validate");
        registry.add("auth.jwt.issuer", () -> "auth-service-integration-test");
        registry.add("auth.jwt.private-key", TestCryptoFixtures::escapedPrivateKeyPem);
        registry.add("auth.jwt.public-key", TestCryptoFixtures::escapedPublicKeyPem);
        registry.add("auth.jwt.default-token-ttl-seconds", () -> "900");
        registry.add("auth.internal.api-key", () -> INTERNAL_API_KEY);
    }

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .standaloneSetup(
                        new AccessTokenController(tokenApplicationService),
                        new TokenIntrospectionController(tokenIntrospectionService))
                .setControllerAdvice(new GlobalExceptionHandler(responseMapper))
                .addFilters(requestCorrelationFilter)
                .build();
        jdbcTemplate.update("delete from oauth_access_tokens");
        jdbcTemplate.update("delete from signature_audit_logs");
        jdbcTemplate.update("delete from api_audit_logs");
        jdbcTemplate.update("""
                update client_public_keys public_key
                join api_clients client on client.id = public_key.api_client_id
                set public_key.public_key_pem = ?
                where client.client_id = ?
                """, TestCryptoFixtures.PUBLIC_KEY_PEM, SEED_CLIENT_ID);
    }

    @Test
    void flywayMigrationAndSeedDataAreAvailable() {
        Integer successfulMigrations = jdbcTemplate.queryForObject(
                "select count(*) from flyway_schema_history where success = 1",
                Integer.class);
        Integer seededClientCount = jdbcTemplate.queryForObject(
                "select count(*) from api_clients where client_id = ? and status = 'ACTIVE'",
                Integer.class,
                SEED_CLIENT_ID);
        Integer activeScopeCount = jdbcTemplate.queryForObject(
                """
                        select count(*)
                        from client_scopes scope
                        join api_clients client on client.id = scope.api_client_id
                        where client.client_id = ? and scope.is_active = true
                        """,
                Integer.class,
                SEED_CLIENT_ID);
        Integer successResponseMappingCount = jdbcTemplate.queryForObject(
                "select count(*) from response_code_mappings where response_code = '2007300'",
                Integer.class);

        assertThat(successfulMigrations).isGreaterThanOrEqualTo(4);
        assertThat(seededClientCount).isEqualTo(1);
        assertThat(activeScopeCount).isEqualTo(2);
        assertThat(successResponseMappingCount).isEqualTo(1);
    }

    @Test
    void accessTokenPositivePersistsTokenAndAuditsThenIntrospectsActiveToken() throws Exception {
        String timestamp = currentSnapTimestamp();
        String signature = TestCryptoFixtures.sign(SEED_CLIENT_ID + "|" + timestamp);

        MvcResult tokenResult = mockMvc.perform(post(ACCESS_TOKEN_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-TIMESTAMP", timestamp)
                        .header("X-CLIENT-KEY", SEED_CLIENT_ID)
                        .header("X-SIGNATURE", signature)
                        .header("X-Forwarded-For", "127.0.0.1")
                        .header(HttpHeaders.USER_AGENT, "integration-test")
                        .content("""
                                {
                                  "grantType": "client_credentials",
                                  "additionalInfo": {}
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(header().string("X-TIMESTAMP", timestamp))
                .andExpect(header().string("X-CLIENT-KEY", SEED_CLIENT_ID))
                .andExpect(jsonPath("$.responseCode").value("2007300"))
                .andExpect(jsonPath("$.responseMessage").value("Successful"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value("900"))
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andReturn();

        String accessToken = readAccessToken(tokenResult);

        Map<String, Object> tokenMetadata = jdbcTemplate.queryForMap("""
                select token_hash, token_type, scopes
                from oauth_access_tokens token
                join api_clients client on client.id = token.api_client_id
                where client.client_id = ?
                """, SEED_CLIENT_ID);
        assertThat(tokenMetadata.get("token_hash")).isNotEqualTo(accessToken);
        assertThat((String) tokenMetadata.get("token_hash")).hasSize(64);
        assertThat(tokenMetadata.get("token_type")).isEqualTo("Bearer");
        assertThat(tokenMetadata.get("scopes")).isEqualTo("openid snap:auth:token");
        assertThat(count("oauth_access_tokens")).isEqualTo(1);

        assertThat(count("""
                signature_audit_logs
                where client_id = ? and signature_type = 'AUTH'
                  and validation_result = 'SUCCESS' and failure_reason is null
                """, SEED_CLIENT_ID)).isEqualTo(1);
        assertThat(count("""
                api_audit_logs
                where client_id = ? and endpoint_path = ? and http_status = 200 and response_code = '2007300'
                """, SEED_CLIENT_ID, ACCESS_TOKEN_PATH)).isEqualTo(1);

        mockMvc.perform(post(INTROSPECTION_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-INTERNAL-API-KEY", INTERNAL_API_KEY)
                        .content("""
                                {
                                  "token": "%s"
                                }
                                """.formatted(accessToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(true))
                .andExpect(jsonPath("$.clientId").value(SEED_CLIENT_ID))
                .andExpect(jsonPath("$.scope").value("openid snap:auth:token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.subject").value(SEED_CLIENT_ID))
                .andExpect(jsonPath("$.additionalInfo.jti").isNotEmpty());
    }

    @Test
    void invalidSignatureReturnsUnauthorizedAndPersistsFailureAuditsWithoutToken() throws Exception {
        String timestamp = currentSnapTimestamp();

        mockMvc.perform(post(ACCESS_TOKEN_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-TIMESTAMP", timestamp)
                        .header("X-CLIENT-KEY", SEED_CLIENT_ID)
                        .header("X-SIGNATURE", "not-base64!")
                        .header("X-Forwarded-For", "127.0.0.1")
                        .content("""
                                {
                                  "grantType": "client_credentials",
                                  "additionalInfo": {}
                                }
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.responseCode").value("4017300"))
                .andExpect(jsonPath("$.responseMessage").value("Unauthorized"));

        assertThat(count("oauth_access_tokens")).isZero();
        assertThat(count("""
                signature_audit_logs
                where client_id = ? and signature_type = 'AUTH'
                  and validation_result = 'FAILED' and failure_reason = 'INVALID_SIGNATURE_FORMAT'
                """, SEED_CLIENT_ID)).isEqualTo(1);
        assertThat(count("""
                api_audit_logs
                where client_id = ? and endpoint_path = ? and http_status = 401 and response_code = '4017300'
                """, SEED_CLIENT_ID, ACCESS_TOKEN_PATH)).isEqualTo(1);
    }

    @Test
    void malformedTokenIntrospectionReturnsInactive() throws Exception {
        mockMvc.perform(post(INTROSPECTION_PATH)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("X-INTERNAL-API-KEY", INTERNAL_API_KEY)
                        .content("""
                                {
                                  "token": "not-a-jwt"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.active").value(false));
    }

    @Test
    void accessTokenRouteIsRegisteredInRealApplicationContext() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        ResponseEntity<String> response = restTemplate.postForEntity(
                "http://localhost:" + port + ACCESS_TOKEN_PATH,
                new HttpEntity<>("{}", headers),
                String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).contains("\"responseCode\":\"4007302\"");
    }

    @Test
    void tokenIntrospectionRouteIsRegisteredInRealApplicationContext() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("X-INTERNAL-API-KEY", INTERNAL_API_KEY);

        ResponseEntity<String> response = restTemplate.postForEntity(
                "http://localhost:" + port + INTROSPECTION_PATH,
                new HttpEntity<>("{}", headers),
                String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).contains("\"responseCode\":\"4007302\"");
    }

    private String currentSnapTimestamp() {
        return OffsetDateTime.now(ZoneOffset.UTC)
                .truncatedTo(ChronoUnit.SECONDS)
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    }

    private String readAccessToken(MvcResult result) throws Exception {
        JsonNode body = objectMapper.readTree(result.getResponse().getContentAsString());
        return body.get("accessToken").asText();
    }

    private int count(String tableExpression, Object... args) {
        Integer count = jdbcTemplate.queryForObject("select count(*) from " + tableExpression, Integer.class, args);
        return count == null ? 0 : count;
    }

    @TestConfiguration
    static class ServiceBeanConfiguration {

        @Bean
        @ConditionalOnMissingBean(AuditService.class)
        AuditService auditService(
                SignatureAuditLogJpaRepository signatureAuditLogRepository,
                ApiAuditLogJpaRepository apiAuditLogRepository,
                ApiClientJpaRepository apiClientRepository,
                SnapResponseCodeMapper responseCodeMapper) {
            return new AuditService(
                    signatureAuditLogRepository,
                    apiAuditLogRepository,
                    apiClientRepository,
                    responseCodeMapper);
        }

        @Bean
        @ConditionalOnMissingBean(ClientCredentialService.class)
        ClientCredentialService clientCredentialService(
                ApiClientJpaRepository apiClientRepository,
                ClientPublicKeyJpaRepository publicKeyRepository,
                ClientScopeJpaRepository scopeRepository,
                SnapResponseCodeMapper responseCodeMapper,
                Clock clock) {
            return new ClientCredentialService(
                    apiClientRepository,
                    publicKeyRepository,
                    scopeRepository,
                    responseCodeMapper,
                    clock);
        }

        @Bean
        @ConditionalOnMissingBean(TokenMetadataService.class)
        TokenMetadataService tokenMetadataService(
                OauthAccessTokenJpaRepository accessTokenRepository,
                ApiClientJpaRepository apiClientRepository,
                SnapResponseCodeMapper responseCodeMapper,
                Clock clock) {
            return new TokenMetadataService(
                    accessTokenRepository,
                    apiClientRepository,
                    responseCodeMapper,
                    clock);
        }

        @Bean
        @ConditionalOnMissingBean(JwtTokenService.class)
        JwtTokenService jwtTokenService(
                JwtProperties jwtProperties,
                TokenMetadataService tokenMetadataService,
                Clock clock) {
            return new JwtTokenService(jwtProperties, tokenMetadataService, clock);
        }

        @Bean
        @ConditionalOnMissingBean(TokenApplicationService.class)
        TokenApplicationService tokenApplicationService(
                SnapRequestValidator requestValidator,
                ClientCredentialService clientCredentialService,
                SignatureVerifier signatureVerifier,
                JwtTokenService jwtTokenService,
                AuditService auditService,
                SnapResponseCodeMapper responseCodeMapper,
                SnapResponseMapper responseMapper,
                TokenMetrics tokenMetrics) {
            return new TokenApplicationService(
                    requestValidator,
                    clientCredentialService,
                    signatureVerifier,
                    jwtTokenService,
                    auditService,
                    responseCodeMapper,
                    responseMapper,
                    tokenMetrics);
        }

        @Bean
        @ConditionalOnMissingBean(TokenIntrospectionService.class)
        TokenIntrospectionService tokenIntrospectionService(
                OauthAccessTokenJpaRepository accessTokenRepository,
                JwtProperties jwtProperties,
                SnapResponseCodeMapper responseCodeMapper,
                Clock clock) {
            return new TokenIntrospectionService(
                    accessTokenRepository,
                    jwtProperties,
                    responseCodeMapper,
                    clock);
        }
    }
}
