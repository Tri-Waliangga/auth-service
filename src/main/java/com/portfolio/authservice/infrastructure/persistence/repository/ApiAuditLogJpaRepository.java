package com.portfolio.authservice.infrastructure.persistence.repository;

import com.portfolio.authservice.infrastructure.persistence.entity.ApiAuditLogEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ApiAuditLogJpaRepository extends JpaRepository<ApiAuditLogEntity, Long> {
}
