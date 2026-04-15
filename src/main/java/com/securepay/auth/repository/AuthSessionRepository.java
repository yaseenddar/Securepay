package com.securepay.auth.repository;

import com.securepay.auth.model.AuthSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuthSessionRepository extends JpaRepository<AuthSession, UUID> {

    Optional<AuthSession> findByJti(String jti);

    @Query("""
            SELECT COUNT(s) > 0 FROM AuthSession s
            WHERE s.user.id = :userId
            AND s.deviceHash != :deviceHash
            AND s.revoked = false
            AND s.expiresAt > :now
            """)
    boolean existsConcurrentSessionFromDifferentDevice(
            @Param("userId") UUID userId,
            @Param("deviceHash") String deviceHash,
            @Param("now") LocalDateTime now
    );

    @Modifying
    @Transactional
    @Query("UPDATE AuthSession s SET s.revoked = true, s.revokedAt = :now WHERE s.user.id = :userId AND s.revoked = false")
    void revokeAllByUserId(@Param("userId") UUID userId, @Param("now") LocalDateTime now);

    @Modifying
    @Transactional
    @Query("""
            UPDATE AuthSession s SET s.revoked = true, s.revokedAt = :now
            WHERE s.user.id = :userId AND s.deviceHash = :deviceHash AND s.revoked = false
            """)
    void revokeAllByUserIdAndDeviceHash(
            @Param("userId") UUID userId,
            @Param("deviceHash") String deviceHash,
            @Param("now") LocalDateTime now
    );

    Optional<AuthSession> findFirstByUser_IdAndDeviceHashAndRevokedFalseAndExpiresAtAfterOrderByIssuedAtDesc(
            UUID userId,
            String deviceHash,
            LocalDateTime now
    );

    Optional<AuthSession> findFirstByUser_IdAndRevokedFalseAndExpiresAtAfterOrderByIssuedAtDesc(
            UUID userId,
            LocalDateTime now
    );

    @Modifying
    @Transactional
    @Query("DELETE FROM AuthSession s WHERE s.expiresAt < :cutoff OR (s.revoked = true AND s.revokedAt < :cutoff)")
    int deleteExpiredSessions(@Param("cutoff") LocalDateTime cutoff);
}
