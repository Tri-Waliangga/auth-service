package com.portfolio.authservice.infrastructure.persistence.repository;

import com.portfolio.authservice.infrastructure.persistence.entity.ApiClientEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ApiClientJpaRepository extends JpaRepository<ApiClientEntity, Long> {

    String ACTIVE_STATUS = "ACTIVE";

    Optional<ApiClientEntity> findByClientIdAndStatus(String clientId, String status);

    default Optional<ApiClientEntity> findActiveByClientId(String clientId) {
        return findByClientIdAndStatus(clientId, ACTIVE_STATUS);
    }
}
