package com.portfolio.authservice.infrastructure.persistence.repository;

import com.portfolio.authservice.infrastructure.persistence.entity.ClientScopeEntity;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ClientScopeJpaRepository extends JpaRepository<ClientScopeEntity, Long> {

    List<ClientScopeEntity> findByApiClient_IdAndActiveTrue(Long apiClientId);

    default List<ClientScopeEntity> findByApiClientIdAndIsActiveTrue(Long apiClientId) {
        return findByApiClient_IdAndActiveTrue(apiClientId);
    }
}
