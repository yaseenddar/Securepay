package com.securepay.auth.model;


import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Represents a known device for a user.
 *
 * DESIGN DECISIONS:
 * - device_hash: SHA-256 of (userAgent + ipSubnet + timezone)
 *   Not raw IP — too volatile. Not full UA — too granular (browser updates break it).
 *   Subnet gives network-level signal, timezone adds geographic signal.
 *
 * - is_trusted: user can explicitly mark a device as trusted.
 *   Trusted devices get lower risk scores even on unusual times.
 *
 * - first_seen_at vs last_seen_at: gap between these tells you
 *   if a "known" device was just created minutes ago (red flag).
 */
@Entity
@Table(name = "device_fingerprints", schema = "auth")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DeviceFingerprint {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)   // LAZY: don't load User on every device query
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "device_hash", nullable = false, length = 64)
    private String deviceHash;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "ip_subnet", length = 20)
    private String ipSubnet;              // e.g. "192.168.1" — /24 subnet

    @Column(name = "timezone", length = 50)
    private String timezone;

    @Column(name = "is_trusted")
    @Builder.Default
    private boolean isTrusted = false;

    @Column(name = "first_seen_at", updatable = false)
    @Builder.Default
    private LocalDateTime firstSeenAt = LocalDateTime.now();

    @Column(name = "last_seen_at")
    @Builder.Default
    private LocalDateTime lastSeenAt = LocalDateTime.now();

    // ── Domain logic ──────────────────────────────────────────────────────

    /**
     * A device that appeared very recently is suspicious even if technically "known".
     * Used by RiskEvaluatorService to add weight to unknown-device score.
     */
    public boolean isNewDevice() {
        return firstSeenAt.isAfter(LocalDateTime.now().minusHours(24));
    }

    public void updateLastSeen() {
        this.lastSeenAt = LocalDateTime.now();
    }
}