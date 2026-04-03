package com.securepay.auth.model;


import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Represents a live authentication session.
 *
 * DESIGN DECISIONS:
 * - jti (JWT ID): unique identifier embedded in JWT payload.
 *   On every request, filter extracts jti from token and queries this table.
 *   If revoked=true → reject immediately, even if token signature is valid.
 *   This solves the fundamental JWT statelessness problem for revocation.
 *
 * - risk_level stored here: so downstream services (Transaction Service)
 *   can receive it in token claims and decide auth strength required.
 *
 * - step_up_done: once user completes TOTP step-up, token is reissued
 *   with this = true. Transaction Service checks this for high-value txns.
 *
 * - expires_at in DB: allows background job to clean up expired sessions.
 *   Without this, sessions table grows unboundedly.
 *
 * WHY NO @Version here?
 * Revocation is the only mutation on this entity.
 * It's a one-way transition (false → true), not a concurrent update scenario.
 * Optimistic locking would add noise without benefit.
 */
@Entity
@Table(name = "auth_sessions", schema = "auth")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthSession {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "device_hash", nullable = false, length = 64)
    private String deviceHash;

    @Column(name = "jti", nullable = false, unique = true)
    private String jti;

    @Enumerated(EnumType.STRING)
    @Column(name = "risk_level", nullable = false, length = 10)
    private RiskLevel riskLevel;

    @Column(name = "step_up_done")
    @Builder.Default
    private boolean stepUpDone = false;

    @Column(name = "issued_at", updatable = false)
    @Builder.Default
    private LocalDateTime issuedAt = LocalDateTime.now();

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "revoked")
    @Builder.Default
    private boolean revoked = false;

    @Column(name = "revoked_at")
    private LocalDateTime revokedAt;

    // ── Domain logic ──────────────────────────────────────────────────────

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }

    /**
     * One-way revocation. Idempotent — safe to call multiple times.
     * Caller must save() after calling this.
     */
    public void revoke() {
        if (!this.revoked) {
            this.revoked = true;
            this.revokedAt = LocalDateTime.now();
        }
    }

    public boolean isValid() {
        return !revoked && !isExpired();
    }
}
