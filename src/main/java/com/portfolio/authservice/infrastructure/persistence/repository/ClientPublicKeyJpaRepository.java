package com.portfolio.authservice.infrastructure.persistence.repository;

import com.portfolio.authservice.infrastructure.persistence.entity.ClientPublicKeyEntity;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ClientPublicKeyJpaRepository extends JpaRepository<ClientPublicKeyEntity, Long> {

    @Query("""
            select publicKey
            from ClientPublicKeyEntity publicKey
            where publicKey.apiClient.id = :apiClientId
              and publicKey.status = 'ACTIVE'
              and publicKey.validFrom <= :now
              and (publicKey.validTo is null or publicKey.validTo > :now)
            order by publicKey.validFrom desc
            """)
    List<ClientPublicKeyEntity> findActiveKeysByApiClientId(
            @Param("apiClientId") Long apiClientId,
            @Param("now") Instant now);

    @Query("""
            select publicKey
            from ClientPublicKeyEntity publicKey
            where publicKey.apiClient.id = :apiClientId
              and publicKey.keyId = :keyId
              and publicKey.status = 'ACTIVE'
              and publicKey.validFrom <= :now
              and (publicKey.validTo is null or publicKey.validTo > :now)
            order by publicKey.validFrom desc
            """)
    List<ClientPublicKeyEntity> findActiveKeysByApiClientIdAndKeyId(
            @Param("apiClientId") Long apiClientId,
            @Param("keyId") String keyId,
            @Param("now") Instant now);

    default Optional<ClientPublicKeyEntity> findActivePublicKeyByClient(Long apiClientId, Instant now) {
        return findActiveKeysByApiClientId(apiClientId, now).stream().findFirst();
    }

    default Optional<ClientPublicKeyEntity> findActivePublicKeyByClientAndKeyId(
            Long apiClientId,
            String keyId,
            Instant now) {
        return findActiveKeysByApiClientIdAndKeyId(apiClientId, keyId, now).stream().findFirst();
    }
}
