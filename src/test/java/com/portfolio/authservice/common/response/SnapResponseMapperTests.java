package com.portfolio.authservice.common.response;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.portfolio.authservice.application.token.IssuedAccessToken;
import com.portfolio.authservice.infrastructure.persistence.entity.ResponseCodeMappingEntity;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import com.portfolio.authservice.interfaces.rest.dto.AccessTokenB2BResponse;
import com.portfolio.authservice.interfaces.rest.dto.SnapErrorResponse;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;

class SnapResponseMapperTests {

    @Test
    void buildsAccessTokenSuccessResponse() {
        SnapResponseMapper mapper = new SnapResponseMapper(new SnapResponseCodeMapper(provider(null)));
        IssuedAccessToken issuedToken = new IssuedAccessToken(
                "jwt-token",
                "Bearer",
                "900",
                "jti",
                Instant.parse("2026-05-08T08:00:00Z"),
                Instant.parse("2026-05-08T08:15:00Z"),
                List.of("openid"));

        AccessTokenB2BResponse response = mapper.accessTokenSuccess(issuedToken);

        assertThat(response.responseCode()).isEqualTo("2007300");
        assertThat(response.responseMessage()).isEqualTo("Successful");
        assertThat(response.accessToken()).isEqualTo("jwt-token");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresIn()).isEqualTo("900");
        assertThat(response.additionalInfo()).isEmpty();
    }

    @Test
    void buildsErrorResponseFromDatabaseMapping() {
        ResponseCodeMappingEntity mapping = new ResponseCodeMappingEntity();
        mapping.setResponseMessage("Conflict from DB");
        ResponseCodeMappingJpaRepository repository = mock(ResponseCodeMappingJpaRepository.class);
        when(repository.findByResponseCode("4097300")).thenReturn(Optional.of(mapping));

        SnapResponseMapper mapper = new SnapResponseMapper(new SnapResponseCodeMapper(provider(repository)));

        SnapErrorResponse response = mapper.error("4097300");

        assertThat(response.responseCode()).isEqualTo("4097300");
        assertThat(response.responseMessage()).isEqualTo("Conflict from DB");
        assertThat(response.additionalInfo()).isEmpty();
    }

    @Test
    void fallsBackForRequiredSnapCodes() {
        SnapResponseMapper mapper = new SnapResponseMapper(new SnapResponseCodeMapper(provider(null)));

        assertThat(mapper.error("4007302").responseMessage()).isEqualTo("Invalid Mandatory Field {field name}");
        assertThat(mapper.error("4017300").responseMessage()).isEqualTo("Unauthorized");
        assertThat(mapper.error("4017301").responseMessage()).isEqualTo("Invalid Token (B2B)");
        assertThat(mapper.error("4037300").responseMessage()).isEqualTo("Forbidden");
        assertThat(mapper.error("4097300").responseMessage()).isEqualTo("Conflict");
        assertThat(mapper.error("5007300").responseMessage()).isEqualTo("General Error");
    }

    @Test
    void resolvesHttpStatusFromResponseCode() {
        SnapResponseMapper mapper = new SnapResponseMapper(new SnapResponseCodeMapper(provider(null)));

        assertThat(mapper.httpStatus("4017301")).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(mapper.httpStatus("not-a-code")).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @SuppressWarnings("unchecked")
    private ObjectProvider<ResponseCodeMappingJpaRepository> provider(ResponseCodeMappingJpaRepository repository) {
        ObjectProvider<ResponseCodeMappingJpaRepository> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(repository);
        return provider;
    }
}
