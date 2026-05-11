package com.portfolio.authservice.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Paths;
import io.swagger.v3.oas.models.examples.Example;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.parameters.HeaderParameter;
import io.swagger.v3.oas.models.parameters.RequestBody;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.tags.Tag;
import java.util.List;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    public static final String INTERNAL_API_KEY_SCHEME = "internalApiKey";

    @Bean
    public OpenAPI authServiceOpenApi() {
        return new OpenAPI()
                .servers(List.of(new Server()
                        .url("http://localhost:3031")
                        .description("Local development server")))
                .tags(List.of(
                        new Tag().name("Auth").description("SNAP B2B authentication endpoints"),
                        new Tag().name("Internal").description("Internal service endpoints protected by X-INTERNAL-API-KEY"),
                        new Tag().name("Dev Utility").description("Local/dev-only helpers. Never enable with production keys."),
                        new Tag().name("Operations").description("Operational health and monitoring references")))
                .components(new Components()
                        .addSecuritySchemes(INTERNAL_API_KEY_SCHEME, new SecurityScheme()
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.HEADER)
                                .name("X-INTERNAL-API-KEY")
                                .description("Internal API key required for /internal/** endpoints.")))
                .info(new Info()
                        .title("Auth Service API")
                        .version("v1")
                        .description("""
                                SNAP security auth-service for Access Token B2B, internal token introspection,
                                internal signature verification, and local development signature generation.
                                Response codes follow SNAP service code 73, for example 2007300, 4007302,
                                4017300, 4017301, 4037300, and 5007300.
                                """));
    }

    @Bean
    public OpenApiCustomizer authServiceOpenApiPaths() {
        return openApi -> {
            Paths paths = openApi.getPaths();
            if (paths == null) {
                paths = new Paths();
                openApi.setPaths(paths);
            }

            paths.putIfAbsent("/cashup/v1.0/access-token/b2b", accessTokenPath());
            paths.putIfAbsent("/internal/v1.0/tokens/introspect", tokenIntrospectionPath());
            paths.putIfAbsent("/internal/v1.0/signatures/verify", internalSignatureVerifyPath());
            paths.putIfAbsent("/cashup/v1.0/utilities/signature-auth", signatureAuthUtilityPath());
            paths.putIfAbsent("/actuator/health", healthPath());
        };
    }

    private PathItem accessTokenPath() {
        Operation operation = new Operation()
                .addTagsItem("Auth")
                .summary("Access Token B2B")
                .description("""
                        Issues a SNAP B2B access token after validating X-CLIENT-KEY, X-TIMESTAMP,
                        X-SIGNATURE, client status, public-key validity, IP policy, and active scopes.
                        Signature string is client_ID|X-TIMESTAMP using SHA256withRSA.
                        SNAP responses include 2007300, 4007300, 4007301, 4007302, 4017300,
                        4037300, and 5007300.
                        """)
                .operationId("issueB2BAccessToken")
                .addParametersItem(header("X-TIMESTAMP", "2026-05-11T16:00:00Z", true))
                .addParametersItem(header("X-CLIENT-KEY", "962489e9-de5d-4eb7-92a4-b07d44d64bf4", true))
                .addParametersItem(header("X-SIGNATURE", "base64-rsa-signature", true))
                .requestBody(jsonRequest("""
                        {
                          "grantType": "client_credentials",
                          "additionalInfo": {}
                        }
                        """))
                .responses(new ApiResponses()
                        .addApiResponse("200", jsonResponse("Successful - SNAP 2007300", """
                                {
                                  "responseCode": "2007300",
                                  "responseMessage": "Successful",
                                  "accessToken": "eyJhbGciOiJSUzI1NiJ9.fake-token",
                                  "tokenType": "Bearer",
                                  "expiresIn": "900",
                                  "additionalInfo": {}
                                }
                                """))
                        .addApiResponse("400", jsonResponse("Bad request - SNAP 4007300, 4007301, 4007302", error("4007302", "Invalid Mandatory Field X-SIGNATURE")))
                        .addApiResponse("401", jsonResponse("Unauthorized - SNAP 4017300", error("4017300", "Unauthorized")))
                        .addApiResponse("403", jsonResponse("Forbidden - SNAP 4037300", error("4037300", "Forbidden")))
                        .addApiResponse("500", jsonResponse("General Error - SNAP 5007300", error("5007300", "General Error"))));
        return new PathItem().post(operation);
    }

    private PathItem tokenIntrospectionPath() {
        Operation operation = new Operation()
                .addTagsItem("Internal")
                .summary("[Internal] Token Introspection")
                .description("""
                        Internal endpoint for validating issued access tokens. Requires X-INTERNAL-API-KEY.
                        Returns active=false for malformed or unknown tokens; expired tokens use SNAP 4017301.
                        SNAP responses include 4007302, 4017301, and 5007300.
                        """)
                .operationId("introspectToken")
                .addSecurityItem(new SecurityRequirement().addList(INTERNAL_API_KEY_SCHEME))
                .requestBody(jsonRequest("""
                        {
                          "token": "eyJhbGciOiJSUzI1NiJ9.fake-token"
                        }
                        """))
                .responses(new ApiResponses()
                        .addApiResponse("200", jsonResponse("Introspection response", """
                                {
                                  "active": true,
                                  "clientId": "962489e9-de5d-4eb7-92a4-b07d44d64bf4",
                                  "scope": "openid snap:auth:token",
                                  "tokenType": "Bearer",
                                  "expiresAt": "2026-05-11T16:15:00Z",
                                  "issuedAt": "2026-05-11T16:00:00Z",
                                  "subject": "962489e9-de5d-4eb7-92a4-b07d44d64bf4",
                                  "additionalInfo": { "jti": "00000000-0000-4000-8000-000000000000" }
                                }
                                """))
                        .addApiResponse("400", jsonResponse("Invalid mandatory field - SNAP 4007302", error("4007302", "Invalid Mandatory Field token")))
                        .addApiResponse("401", jsonResponse("Invalid token - SNAP 4017301", error("4017301", "Invalid Token (B2B)")))
                        .addApiResponse("500", jsonResponse("General Error - SNAP 5007300", error("5007300", "General Error"))));
        return new PathItem().post(operation);
    }

    private PathItem internalSignatureVerifyPath() {
        Operation operation = new Operation()
                .addTagsItem("Internal")
                .summary("[Internal] Verify SNAP Signature")
                .description("""
                        Internal endpoint for verifying SHA256withRSA signatures against the active client public key.
                        Requires X-INTERNAL-API-KEY. SNAP responses include 2007300, 4007302, 4017300, and 5007300.
                        """)
                .operationId("verifyInternalSignature")
                .addSecurityItem(new SecurityRequirement().addList(INTERNAL_API_KEY_SCHEME))
                .requestBody(jsonRequest("""
                        {
                          "clientId": "962489e9-de5d-4eb7-92a4-b07d44d64bf4",
                          "timestamp": "2026-05-11T16:00:00Z",
                          "signature": "base64-rsa-signature",
                          "stringToSign": "962489e9-de5d-4eb7-92a4-b07d44d64bf4|2026-05-11T16:00:00Z"
                        }
                        """))
                .responses(new ApiResponses()
                        .addApiResponse("200", jsonResponse("Signature verification response - SNAP 2007300 or 4017300", """
                                {
                                  "valid": true,
                                  "responseCode": "2007300",
                                  "responseMessage": "Successful",
                                  "failureReason": null,
                                  "additionalInfo": {}
                                }
                                """))
                        .addApiResponse("400", jsonResponse("Invalid mandatory field - SNAP 4007302", error("4007302", "Invalid Mandatory Field clientId")))
                        .addApiResponse("401", jsonResponse("Unauthorized - SNAP 4017300", error("4017300", "Unauthorized")))
                        .addApiResponse("500", jsonResponse("General Error - SNAP 5007300", error("5007300", "General Error"))));
        return new PathItem().post(operation);
    }

    private PathItem signatureAuthUtilityPath() {
        Operation operation = new Operation()
                .addTagsItem("Dev Utility")
                .summary("[Dev/local only] Generate Access Token B2B Signature")
                .description("""
                        WARNING: local/dev utility only. This endpoint is available only with the local or dev profile.
                        Do not enable it in production and never submit production private keys.
                        Generates SHA256withRSA signature for clientId|timestamp to support Postman testing.
                        SNAP validation errors include 4007301 and 4007302.
                        """)
                .operationId("generateAuthSignature")
                .addParametersItem(header("X-TIMESTAMP", "2026-05-11T16:00:00Z", false))
                .addParametersItem(header("X-CLIENT-KEY", "962489e9-de5d-4eb7-92a4-b07d44d64bf4", false))
                .requestBody(jsonRequest("""
                        {
                          "clientId": "962489e9-de5d-4eb7-92a4-b07d44d64bf4",
                          "timestamp": "2026-05-11T16:00:00Z",
                          "privateKeyPem": "-----BEGIN PRIVATE KEY-----\\nFAKE_LOCAL_TEST_KEY\\n-----END PRIVATE KEY-----"
                        }
                        """))
                .responses(new ApiResponses()
                        .addApiResponse("200", jsonResponse("Generated local/dev signature", """
                                {
                                  "signature": "base64-rsa-signature",
                                  "stringToSign": "962489e9-de5d-4eb7-92a4-b07d44d64bf4|2026-05-11T16:00:00Z",
                                  "algorithm": "SHA256withRSA",
                                  "additionalInfo": {}
                                }
                                """))
                        .addApiResponse("400", jsonResponse("Validation error - SNAP 4007301 or 4007302", error("4007302", "Invalid Mandatory Field privateKeyPem"))));
        return new PathItem().post(operation);
    }

    private PathItem healthPath() {
        Operation operation = new Operation()
                .addTagsItem("Operations")
                .summary("Health Check")
                .description("Spring Boot Actuator health endpoint reference for local and deployment monitoring.")
                .operationId("health")
                .responses(new ApiResponses()
                        .addApiResponse("200", jsonResponse("Service health", """
                                {
                                  "status": "UP"
                                }
                                """)));
        return new PathItem().get(operation);
    }

    private HeaderParameter header(String name, String example, boolean required) {
        return (HeaderParameter) new HeaderParameter()
                .name(name)
                .required(required)
                .description(name + " header")
                .example(example);
    }

    private RequestBody jsonRequest(String example) {
        return new RequestBody()
                .required(true)
                .content(jsonContent(example));
    }

    private ApiResponse jsonResponse(String description, String example) {
        return new ApiResponse()
                .description(description)
                .content(jsonContent(example));
    }

    private Content jsonContent(String example) {
        return new Content().addMediaType(org.springframework.http.MediaType.APPLICATION_JSON_VALUE, new MediaType()
                .addExamples("default", new Example().value(example)));
    }

    private String error(String responseCode, String responseMessage) {
        return """
                {
                  "responseCode": "%s",
                  "responseMessage": "%s",
                  "additionalInfo": {}
                }
                """.formatted(responseCode, responseMessage);
    }
}
