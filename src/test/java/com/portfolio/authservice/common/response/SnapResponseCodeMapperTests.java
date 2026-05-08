package com.portfolio.authservice.common.response;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.portfolio.authservice.infrastructure.persistence.entity.ResponseCodeMappingEntity;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

class SnapResponseCodeMapperTests {

    @Test
    void resolvesMessageFromResponseCodeMappingAndReplacesFieldName() {
        ResponseCodeMappingEntity mapping = new ResponseCodeMappingEntity();
        mapping.setResponseMessage("Invalid Mandatory Field {field name}");

        ResponseCodeMappingJpaRepository repository = mock(ResponseCodeMappingJpaRepository.class);
        when(repository.findByResponseCode("4007302")).thenReturn(Optional.of(mapping));

        SnapResponseCodeMapper mapper = new SnapResponseCodeMapper(provider(repository));

        assertThat(mapper.resolveMessage("4007302", "X-CLIENT-KEY"))
                .isEqualTo("Invalid Mandatory Field X-CLIENT-KEY");
    }

    @Test
    void fallsBackWhenRepositoryIsUnavailable() {
        SnapResponseCodeMapper mapper = new SnapResponseCodeMapper(provider(null));

        assertThat(mapper.resolveMessage("4007301", "X-TIMESTAMP"))
                .isEqualTo("Invalid Field Format X-TIMESTAMP");
    }

    @Test
    void resolvesUnauthorizedPublicMessageWithoutReasonPlaceholder() {
        ResponseCodeMappingEntity mapping = new ResponseCodeMappingEntity();
        mapping.setResponseMessage("Unauthorized. [reason]");

        ResponseCodeMappingJpaRepository repository = mock(ResponseCodeMappingJpaRepository.class);
        when(repository.findByResponseCode("4017300")).thenReturn(Optional.of(mapping));

        SnapResponseCodeMapper mapper = new SnapResponseCodeMapper(provider(repository));

        assertThat(mapper.resolvePublicMessage("4017300")).isEqualTo("Unauthorized");
    }

    @SuppressWarnings("unchecked")
    private ObjectProvider<ResponseCodeMappingJpaRepository> provider(ResponseCodeMappingJpaRepository repository) {
        ObjectProvider<ResponseCodeMappingJpaRepository> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(repository);
        return provider;
    }
}
