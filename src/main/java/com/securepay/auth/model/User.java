package com.securepay.auth.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Core user entity.
 *
 * DESIGN DECISIONS:
 * - UUID PK: non-guessable, safe to expose in APIs unlike sequential IDs
 * - password_hash: raw password NEVER stored — BCrypt hashed (cost factor 12)
 * - failed_attempts + locked_until: brute-force lockout without external cache
 * - totp_secret: null until user enrolls step-up auth
 *
 * NO @Version here — optimistic locking on User would cause
 * conflicts on every login (last_seen update). Use explicit
 * field-level locking where needed instead.
 */
@Entity
@Table(name = "users", schema = "auth")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false, unique = true)
    private String phone;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "totp_secret")
    private String totpSecret;

    @Column(name = "totp_enabled")
    @Builder.Default
    private boolean totpEnabled = false;

    @Column(name = "is_active")
    @Builder.Default
    private boolean isActive = true;

    @Column(name = "failed_attempts")
    @Builder.Default
    private int failedAttempts = 0;

    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    @Column(name = "created_at", updatable = false)
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // ── Domain logic methods ──────────────────────────────────────────────

    /**
     * Is this account currently locked?
     * Lockout expires automatically — no manual unlock needed for temporary locks.
     */
    public boolean isLocked() {
        return lockedUntil != null && LocalDateTime.now().isBefore(lockedUntil);
    }

    /**
     * Record a failed login attempt.
     * Locks account for 15 minutes after 5 consecutive failures.
     * IMPORTANT: Caller must save() after calling this.
     */
    public void recordFailedAttempt() {
        this.failedAttempts++;
        if (this.failedAttempts == 5) {
            this.lockedUntil = LocalDateTime.now().plusMinutes(10);
        }
    }

    /**
     * Reset on successful login. set locked null and update the db when user is allowed after 10 mins
     */
    public void resetFailedAttempts() {
        this.failedAttempts = 0;
        this.lockedUntil = null;
    }
}