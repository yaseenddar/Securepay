package com.securepay.auth.service;


import com.securepay.auth.model.DeviceFingerprint;
import com.securepay.auth.model.User;

//─────────────────────────────────────────────────────────────────────────────
//DEVICE FINGERPRINT SERVICE
//Extracts device context from HTTP request, computes hash, manages persistence.
//─────────────────────────────────────────────────────────────────────────────

import com.securepay.auth.repository.DeviceFingerprintRepository;
import jakarta.servlet.http.HttpServletRequest;
import securepay.app.auth.dto.DeviceContext;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.Optional;

@Service
public class DeviceFingerprintService {

 private static final String UNKNOWN = "unknown";

 private final DeviceFingerprintRepository deviceRepo;

 DeviceFingerprintService(DeviceFingerprintRepository deviceRepo) {
     this.deviceRepo = deviceRepo;
 }

 /**
  * Extract DeviceContext from the incoming HTTP request.
  *
  * HEADER EXTRACTION ORDER — each signal explained:
  *
  * ── IP ADDRESS ───────────────────────────────────────────────────────────
  * WHY check X-Forwarded-For before request.getRemoteAddr()?
  *
  * In a microservice architecture, requests arrive at:
  *   Client → [Load Balancer] → [API Gateway] → Auth Service
  *
  * By the time the request hits Auth Service, getRemoteAddr() returns
  * the IP of the API Gateway (e.g. 10.0.0.1) — an internal address.
  * That's useless for device fingerprinting.
  *
  * X-Forwarded-For: <client-ip>, <proxy1-ip>, <proxy2-ip>
  * The FIRST value is always the original client IP.
  * We take index [0] after splitting on comma.
  *
  * SECURITY NOTE: X-Forwarded-For can be spoofed by clients
  * who set it themselves. In production, your load balancer should
  * strip and re-set this header. Trust your infra, not the client.
  *
  * ── USER-AGENT ───────────────────────────────────────────────────────────
  * Normalized to lowercase to prevent "Chrome/120" vs "chrome/120"
  * producing different fingerprints.
  *
  * ── TIMEZONE ─────────────────────────────────────────────────────────────
  * Custom header X-Timezone sent by the client.
  * Expected format: IANA timezone string e.g. "Asia/Kolkata"
  * Falls back to "unknown" if absent (mobile apps may not send this).
  */
 public DeviceContext extractFromRequest(HttpServletRequest request) {
     // ── Extract raw IP ────────────────────────────────────────────────────
     String rawIp = extractClientIp(request);

     // ── Extract /24 subnet ────────────────────────────────────────────────
     String ipSubnet = extractSubnet(rawIp);

     // ── Extract User-Agent ────────────────────────────────────────────────
     String userAgent = request.getHeader("User-Agent");
     if (userAgent == null || userAgent.isBlank()) {
         userAgent = UNKNOWN;
     }
     // Normalize: lowercase prevents hash divergence on case differences
     userAgent = userAgent.toLowerCase().trim();

     // ── Extract timezone ──────────────────────────────────────────────────
     String timezone = request.getHeader("X-Timezone");
     if (timezone == null || timezone.isBlank()) {
         timezone = UNKNOWN;
     }

     // ── Compute deterministic fingerprint hash ────────────────────────────
     String deviceHash = computeHash(userAgent, ipSubnet, timezone);

     return DeviceContext.builder()
             .deviceHash(deviceHash)
             .userAgent(userAgent)
             .ipSubnet(ipSubnet)
             .timezone(timezone)
             .rawIp(rawIp)           // kept for audit logging only, never stored in hash
             .build();
 }

 /**
  * Extract real client IP from request.
  *
  * X-Forwarded-For contains a comma-separated chain of IPs added by each proxy.
  * Format: "clientIp, proxy1Ip, proxy2Ip"
  * We always want the leftmost (original) value.
  *
  * Null/blank check before split — defensive against malformed headers.
  */
 private String extractClientIp(HttpServletRequest request) {
     String forwarded = request.getHeader("X-Forwarded-For");
     if (forwarded != null && !forwarded.isBlank()) {
         // Take first IP in the chain — that's the actual client
         return forwarded.split(",")[0].trim();
     }
     // No proxy header → direct connection → remoteAddr is the real client
     return request.getRemoteAddr();
 }

 /**
  * Extract /24 subnet from a full IPv4 address.
  *
  * "192.168.1.47" → "192.168.1"
  * "10.0.0.200"   → "10.0.0"
  *
  * HOW: split on ".", take first 3 parts, rejoin with ".".
  *
  * EDGE CASES handled:
  * - IPv6 addresses: don't contain 4 dot-separated octets.
  *   We return the raw IP unchanged — no subnet extraction.
  *   IPv6 subnet extraction (/48 or /64) is a future enhancement.
  * - Malformed IP (null, blank, no dots): return "unknown" safely.
  *   A malformed IP still produces a consistent fingerprint across
  *   requests — better than crashing.
  */
 private String extractSubnet(String ip) {
     if (ip == null || ip.isBlank()) return UNKNOWN;

     String[] parts = ip.split("\\.");
     if (parts.length != 4) {
         // Not a valid IPv4 — could be IPv6 or malformed
         return ip; // use as-is — still produces a consistent hash
     }
     // Join first 3 octets — represents the /24 network
     return parts[0] + "." + parts[1] + "." + parts[2];
 }

 /**
  * Compute SHA-256 fingerprint from device signals.
  *
  * INPUT FORMAT: "userAgent|ipSubnet|timezone"
  * The "|" separator prevents collision between:
  *   userAgent="Chrome", subnet="192.168.1", tz="unknown"
  * and:
  *   userAgent="Chrome|192.168.1", subnet="unknown", tz=""
  * Without a separator, these would hash identically — a collision.
  *
  * SHA-256 INTERNALS (understand this, don't just call it):
  * 1. Input string → bytes (UTF-8)
  * 2. MessageDigest pads input to a multiple of 512 bits
  * 3. Processes in 512-bit blocks through 64 rounds of compression
  * 4. Produces a 256-bit (32-byte) digest
  * 5. We hex-encode it → 64 character string
  *
  * THREAD SAFETY:
  * MessageDigest is NOT thread-safe. Each call creates a new instance.
  * getInstance() is cheap — no concern reusing the string, not the digest.
  *
  * NoSuchAlgorithmException from getInstance("SHA-256"):
  * SHA-256 is guaranteed by the Java spec to exist on all JVMs.
  * Wrapping in RuntimeException is the correct pattern — it CANNOT happen.
  * Don't propagate a checked exception that can never be thrown.
  */
 public String computeHash(String userAgent, String ipSubnet, String timezone) {
     try {
         MessageDigest digest = MessageDigest.getInstance("SHA-256");

         // Normalize inputs before hashing — same device must always produce same hash
         String input = normalize(userAgent) + "|"
                      + normalize(ipSubnet)  + "|"
                      + normalize(timezone);

         byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));

         // HexFormat (Java 17+) — no external libs needed
         // formatHex converts each byte to its 2-char hex representation
         // 32 bytes × 2 chars = 64-char string — matches device_hash column length
         return HexFormat.of().formatHex(hashBytes);

     } catch (NoSuchAlgorithmException e) {
         // SHA-256 is mandated by Java spec — this is truly unreachable
         // But we cannot throw checked exceptions from here
         throw new IllegalStateException("SHA-256 not available — JVM is broken", e);
     }
 }

 /**
  * Normalize a fingerprint component before hashing.
  * Null → "unknown", trim whitespace, lowercase.
  * Consistency is critical: same device must ALWAYS produce same hash.
  */
 private String normalize(String value) {
     if (value == null || value.isBlank()) return UNKNOWN;
     return value.trim().toLowerCase();
 }

 /**
  * Find existing device fingerprint or register a new one.
  *
  * HAPPY PATH (device known):
  *   SELECT → found → update lastSeenAt → return
  *
  * FIRST-LOGIN PATH (device new):
  *   SELECT → not found → INSERT → return
  *
  * RACE CONDITION PATH (two concurrent first-logins from same device):
  *   T1: SELECT → not found
  *   T2: SELECT → not found
  *   T1: INSERT → success, commits
  *   T2: INSERT → DataIntegrityViolationException (UNIQUE constraint)
  *   T2: catch → SELECT again → finds T1's row → returns it ✓
  *
  * WHY @Transactional here?
  * The SELECT + UPDATE (updateLastSeen) must be atomic for known devices.
  * Without @Transactional, another thread could delete the device between
  * our SELECT and UPDATE — UPDATE would silently affect 0 rows.
  *
  * The @Transactional on this method uses READ_COMMITTED (default).
  * That's sufficient here — we're not doing balance calculations.
  * SERIALIZABLE would be overkill and hurt performance.
  *
  * NOTE: @Transactional on a non-public method doesn't work with Spring AOP.
  * This must be public for the proxy to intercept it.
  */
 @Transactional
 public DeviceFingerprint findOrRegisterDevice(User user, DeviceContext context) {
     // ── Check if device already known ─────────────────────────────────────
     Optional<DeviceFingerprint> existing =
             deviceRepo.findByUserIdAndDeviceHash(user.getId(), context.getDeviceHash());

     if (existing.isPresent()) {
         // Known device — just refresh lastSeenAt
         // Using @Modifying JPQL update (single UPDATE statement, no entity load)
         deviceRepo.updateLastSeen(
                 user.getId(),
                 context.getDeviceHash(),
                 LocalDateTime.now()
         );
         return existing.get();
     }

     // ── New device — attempt to register ─────────────────────────────────
     DeviceFingerprint newDevice = DeviceFingerprint.builder()
             .user(user)
             .deviceHash(context.getDeviceHash())
             .userAgent(context.getUserAgent())
             .ipSubnet(context.getIpSubnet())
             .timezone(context.getTimezone())
             .isTrusted(false)             // new devices start untrusted
             .firstSeenAt(LocalDateTime.now())
             .lastSeenAt(LocalDateTime.now())
             .build();

     try {
         return deviceRepo.save(newDevice);

     } catch (DataIntegrityViolationException ex) {
         // ── Race condition: concurrent login already inserted this device ──
         // Another thread beat us to the INSERT.
         // The UNIQUE constraint (user_id, device_hash) rejected our INSERT.
         // Re-fetch what the other thread just wrote — must be there now.
         return deviceRepo
                 .findByUserIdAndDeviceHash(user.getId(), context.getDeviceHash())
                 .orElseThrow(() -> new IllegalStateException(
                         // This truly cannot happen: constraint fired = row exists
                         // If we somehow still don't find it, something is deeply wrong
                         "Device constraint violation but row not found — DB inconsistency",
                         ex
                 ));
     }
 }
}
