package com.portfolio.authservice.common.response;

import com.portfolio.authservice.infrastructure.persistence.entity.ResponseCodeMappingEntity;
import com.portfolio.authservice.infrastructure.persistence.repository.ResponseCodeMappingJpaRepository;
import java.util.Map;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class SnapResponseCodeMapper {

    private static final String FIELD_NAME_PLACEHOLDER = "{field name}";
    private static final Map<String, String> FALLBACK_MESSAGES = Map.of(
            "4007300", "Bad Request",
            "4007301", "Invalid Field Format {field name}",
            "4007302", "Invalid Mandatory Field {field name}");

    private final ObjectProvider<ResponseCodeMappingJpaRepository> repositoryProvider;

    public SnapResponseCodeMapper(ObjectProvider<ResponseCodeMappingJpaRepository> repositoryProvider) {
        this.repositoryProvider = repositoryProvider;
    }

    public String resolveMessage(String responseCode) {
        return resolveMessage(responseCode, null);
    }

    public String resolveMessage(String responseCode, String fieldName) {
        String responseMessage = lookupResponseMessage(responseCode);
        if (StringUtils.hasText(fieldName)) {
            return responseMessage.replace(FIELD_NAME_PLACEHOLDER, fieldName);
        }
        return responseMessage;
    }

    private String lookupResponseMessage(String responseCode) {
        ResponseCodeMappingJpaRepository repository = repositoryProvider.getIfAvailable();
        if (repository == null) {
            return fallbackMessage(responseCode);
        }

        return repository.findByResponseCode(responseCode)
                .map(ResponseCodeMappingEntity::getResponseMessage)
                .orElseGet(() -> fallbackMessage(responseCode));
    }

    private String fallbackMessage(String responseCode) {
        return FALLBACK_MESSAGES.getOrDefault(responseCode, "General Error");
    }
}
