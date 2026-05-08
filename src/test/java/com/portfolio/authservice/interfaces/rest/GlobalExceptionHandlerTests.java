package com.portfolio.authservice.interfaces.rest;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.portfolio.authservice.common.error.SnapConflictException;
import com.portfolio.authservice.common.error.SnapForbiddenException;
import com.portfolio.authservice.common.error.SnapGeneralException;
import com.portfolio.authservice.common.error.SnapUnauthorizedException;
import com.portfolio.authservice.common.error.SnapValidationException;
import com.portfolio.authservice.common.response.SnapResponseCodeMapper;
import com.portfolio.authservice.common.response.SnapResponseMapper;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@ExtendWith(OutputCaptureExtension.class)
class GlobalExceptionHandlerTests {

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .standaloneSetup(new ThrowingController())
                .setControllerAdvice(new GlobalExceptionHandler(new SnapResponseMapper(responseCodeMapper())))
                .build();
    }

    @Test
    void snapValidationExceptionReturnsSnapEnvelope() throws Exception {
        mockMvc.perform(get("/throw/validation"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseCode").value("4007302"))
                .andExpect(jsonPath("$.responseMessage").value("Invalid Mandatory Field X-CLIENT-KEY"))
                .andExpect(jsonPath("$.additionalInfo").isMap());
    }

    @Test
    void snapUnauthorizedExceptionReturnsUnauthorizedEnvelope() throws Exception {
        mockMvc.perform(get("/throw/unauthorized"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.responseCode").value("4017300"))
                .andExpect(jsonPath("$.responseMessage").value("Unauthorized"));
    }

    @Test
    void invalidTokenExceptionReturnsInvalidTokenEnvelope() throws Exception {
        mockMvc.perform(get("/throw/invalid-token"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.responseCode").value("4017301"))
                .andExpect(jsonPath("$.responseMessage").value("Invalid Token (B2B)"));
    }

    @Test
    void forbiddenConflictAndGeneralExceptionsReturnSnapEnvelopes() throws Exception {
        mockMvc.perform(get("/throw/forbidden"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.responseCode").value("4037300"));

        mockMvc.perform(get("/throw/conflict"))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.responseCode").value("4097300"));

        mockMvc.perform(get("/throw/general"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.responseCode").value("5007300"));
    }

    @Test
    void malformedJsonDoesNotExposeSpringDefaultErrorJson() throws Exception {
        mockMvc.perform(post("/echo")
                        .contentType(MediaType.APPLICATION_JSON)
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
    void missingHeaderReturnsInvalidMandatoryFieldEnvelope() throws Exception {
        mockMvc.perform(get("/required-header"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.responseCode").value("4007302"))
                .andExpect(jsonPath("$.timestamp").doesNotExist())
                .andExpect(jsonPath("$.error").doesNotExist())
                .andExpect(jsonPath("$.path").doesNotExist())
                .andExpect(jsonPath("$.trace").doesNotExist())
                .andExpect(jsonPath("$.message").doesNotExist());
    }

    @Test
    void unsupportedFrameworkErrorDoesNotExposeSpringDefaultErrorJson() throws Exception {
        mockMvc.perform(get("/echo"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.responseCode").value("5007300"))
                .andExpect(jsonPath("$.error").doesNotExist());
    }

    @Test
    void genericExceptionReturnsGeneralErrorEnvelope() throws Exception {
        mockMvc.perform(get("/throw/generic"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.responseCode").value("5007300"))
                .andExpect(jsonPath("$.responseMessage").value("General Error"))
                .andExpect(jsonPath("$.timestamp").doesNotExist())
                .andExpect(jsonPath("$.error").doesNotExist())
                .andExpect(jsonPath("$.path").doesNotExist())
                .andExpect(jsonPath("$.trace").doesNotExist())
                .andExpect(jsonPath("$.message").doesNotExist());
    }

    @Test
    void logsRequestIdAndSanitizedMetadataWithoutSensitiveValues(CapturedOutput output) throws Exception {
        mockMvc.perform(get("/throw/generic")
                        .requestAttr(RequestCorrelationFilter.REQUEST_ID_ATTRIBUTE, "request-id-456")
                        .header("X-SIGNATURE", "secret-signature")
                        .header("Authorization", "Bearer secret-token"))
                .andExpect(status().isInternalServerError());

        assertThat(output).contains("requestId=request-id-456");
        assertThat(output).contains("path=/throw/generic");
        assertThat(output).contains("responseCode=5007300");
        assertThat(output).contains("exceptionClass=java.lang.IllegalStateException");
        assertThat(output).doesNotContain("secret-signature");
        assertThat(output).doesNotContain("secret-token");
        assertThat(output).doesNotContain("raw-secret-message");
    }

    @SuppressWarnings("unchecked")
    private SnapResponseCodeMapper responseCodeMapper() {
        ObjectProvider<ResponseCodeMappingJpaRepository> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(null);
        return new SnapResponseCodeMapper(provider);
    }

    @RestController
    static class ThrowingController {

        @GetMapping("/throw/validation")
        void validation() {
            throw new SnapValidationException(
                    "4007302",
                    "Invalid Mandatory Field X-CLIENT-KEY",
                    "Invalid mandatory field: X-CLIENT-KEY");
        }

        @GetMapping("/throw/unauthorized")
        void unauthorized() {
            throw new SnapUnauthorizedException("4017300", "Unauthorized", "INVALID_SIGNATURE");
        }

        @GetMapping("/throw/invalid-token")
        void invalidToken() {
            throw new SnapUnauthorizedException("4017301", "Invalid Token (B2B)", "TOKEN_EXPIRED");
        }

        @GetMapping("/throw/forbidden")
        void forbidden() {
            throw new SnapForbiddenException("Forbidden", "NO_SCOPE");
        }

        @GetMapping("/throw/conflict")
        void conflict() {
            throw new SnapConflictException("Conflict", "DUPLICATE_REQUEST");
        }

        @GetMapping("/throw/general")
        void general() {
            throw new SnapGeneralException("General Error", "UNEXPECTED");
        }

        @GetMapping("/throw/generic")
        void generic() {
            throw new IllegalStateException("raw-secret-message");
        }

        @GetMapping("/required-header")
        void requiredHeader(@RequestHeader("X-MANDATORY") String mandatoryHeader) {
        }

        @PostMapping("/echo")
        Map<String, Object> echo(@RequestBody Map<String, Object> body) {
            return body;
        }
    }
}
