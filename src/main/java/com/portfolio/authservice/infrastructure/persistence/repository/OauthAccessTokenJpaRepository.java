package com.portfolio.authservice.infrastructure.persistence.repository;

import com.portfolio.authservice.infrastructure.persistence.entity.OauthAccessTokenEntity;
import java.time.Instant;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface OauthAccessTokenJpaRepository extends JpaRepository<OauthAccessTokenEntity, Long> {

    Optional<OauthAccessTokenEntity> findByTokenJti(String tokenJti);

    Optional<OauthAccessTokenEntity> findByTokenHash(String tokenHash);

    @Query("""
            select accessToken
            from OauthAccessTokenEntity accessToken
            where accessToken.tokenHash = :tokenHash
              and accessToken.revokedAt is null
              and accessToken.expiresAt > :now
            """)
    Optional<OauthAccessTokenEntity> findActiveByTokenHash(
            @Param("tokenHash") String tokenHash,
            @Param("now") Instant now);
}
