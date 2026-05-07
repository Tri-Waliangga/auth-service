package com.portfolio.authservice.infrastructure.persistence.repository;

import com.portfolio.authservice.infrastructure.persistence.entity.SignatureAuditLogEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SignatureAuditLogJpaRepository extends JpaRepository<SignatureAuditLogEntity, Long> {
}
