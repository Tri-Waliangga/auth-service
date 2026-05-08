package com.portfolio.authservice.infrastructure.persistence.repository;

import com.portfolio.authservice.infrastructure.persistence.entity.ResponseCodeMappingEntity;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ResponseCodeMappingJpaRepository extends JpaRepository<ResponseCodeMappingEntity, Long> {

    Optional<ResponseCodeMappingEntity> findByResponseCode(String responseCode);

    Optional<ResponseCodeMappingEntity> findByServiceCodeAndCaseCode(String serviceCode, String caseCode);
}
