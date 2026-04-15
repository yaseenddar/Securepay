package com.securepay.auth.repository;

import com.securepay.auth.model.DeviceFingerprint;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

//─────────────────────────────────────────────────────────────────────────────
//DEVICE FINGERPRINT REPOSITORY
//─────────────────────────────────────────────────────────────────────────────

@Repository
public interface DeviceFingerprintRepository extends JpaRepository<DeviceFingerprint, UUID> {

 /**
  * Hot path: called on every login.
  * Hits idx_device_hash_user composite index.
  * Returns empty if device is unknown for this user.
  */
 @Query("SELECT d FROM DeviceFingerprint d WHERE d.user.id = :userId AND d.deviceHash = :deviceHash")
 Optional<DeviceFingerprint> findByUserIdAndDeviceHash(
         @Param("userId") UUID userId,
         @Param("deviceHash") String deviceHash
 );

 /**
  * List all trusted devices for a user — shown on /devices endpoint.
  */
 @Query("SELECT d FROM DeviceFingerprint d WHERE d.user.id = :userId ORDER BY d.lastSeenAt DESC")
 List<DeviceFingerprint> findAllByUserId(@Param("userId") UUID userId);

 /**
  * Bulk update last_seen without loading entities.
  *
  * WHY @Modifying + JPQL update instead of load → set → save?
  * Loading the entity just to update one timestamp is wasteful.
  * This executes a single UPDATE statement directly.
  * @Modifying tells Spring Data this is a write operation,
  * required for @Query that mutates data.
  */
 @Modifying
 @Transactional
 @Query("UPDATE DeviceFingerprint d SET d.lastSeenAt = :now WHERE d.user.id = :userId AND d.deviceHash = :deviceHash")
 void updateLastSeen(
         @Param("userId") UUID userId,
         @Param("deviceHash") String deviceHash,
         @Param("now") LocalDateTime now
 );
}
