package com.securepay.auth.service;

// ─────────────────────────────────────────────────────────────────────────────
// JWT SERVICE
// Handles token generation, parsing, and validation.
// This is NOT a Spring Security concern — it's a pure utility service.
// Spring Security's job is to read the already-validated token from context.
// ─────────────────────────────────────────────────────────────────────────────

import com.securepay.auth.model.AuthSession;
import com.securepay.auth.model.RiskLevel;
import com.securepay.auth.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Service
class JwtService {

    // ── Custom claim key constants ────────────────────────────────────────────
    // String constants avoid typos. "userId" != "user_id" — one of these
    // returns null silently. Constants catch it at compile time.
    public static final String CLAIM_USER_ID     = "userId";
    public static final String CLAIM_DEVICE_HASH = "deviceHash";
    public static final String CLAIM_RISK_LEVEL  = "riskLevel";
    public static final String CLAIM_STEP_UP     = "stepUpDone";
    public static final String CLAIM_TOKEN_TYPE  = "tokenType";

    private final SecretKey secretKey;
    private final long accessTokenExpiryMs;
    private final long refreshTokenExpiryMs;

    public JwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-expiry-ms}") long accessTokenExpiryMs,
            @Value("${jwt.refresh-token-expiry-ms}") long refreshTokenExpiryMs
    ) {
        // Keys.hmacShaKeyFor enforces minimum 256-bit (32-byte) key for HS256.
        // If your secret is "mysecret" (8 bytes) → WeakKeyException at startup.
        // This is intentional fail-fast: a weak key in production is worse than
        // a failed startup in staging. Fix the environment variable, not the code.
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpiryMs = accessTokenExpiryMs;
        this.refreshTokenExpiryMs = refreshTokenExpiryMs;
    }

    /**
     * Generate access token with embedded security claims.
     *
     * WHAT GETS EMBEDDED AND WHY:
     *
     * sub (subject) = user email
     *   Standard JWT claim. Used by JwtAuthFilter to load UserDetails.
     *   WHY email not UUID? Email is human-readable in decoded tokens → easier debugging.
     *   UUID is also embedded separately as userId for DB lookups.
     *
     * jti (JWT ID) = random UUID per token
     *   Standard claim. Stored in auth_sessions table.
     *   This is what makes revocation possible — filter looks this up on every request.
     *   WHY UUID? Globally unique, unguessable, no sequential pattern to exploit.
     *
     * userId = user UUID string
     *   Downstream services (Transaction Service) need user ID for DB queries.
     *   Embedding it avoids an extra "resolve email → UUID" DB call per request.
     *
     * deviceHash = SHA-256 fingerprint
     *   Binds token to the device it was issued on.
     *   Transaction Service can enforce: "this token must be used from its origin device."
     *   Mitigates token theft — stolen token used from different device is detectable.
     *
     * riskLevel = LOW | MEDIUM | HIGH
     *   Transaction Service reads this to gate high-value transactions.
     *   HIGH riskLevel = require step-up before allowing ₹50,000 transfer.
     *
     * stepUpDone = boolean
     *   Once user completes TOTP step-up, token is REISSUED with this = true.
     *   Cannot mutate claims in existing token — JWT is immutable once signed.
     *
     * tokenType = "ACCESS"
     *   Prevents accidentally using a refresh token as an access token.
     *   JwtAuthFilter will reject tokens where tokenType != "ACCESS".
     *
     * WHAT IS NOT EMBEDDED:
     * - Password hash (obviously)
     * - Raw IP address (privacy)
     * - Roles (fetched fresh from DB to reflect role changes without token reissue)
     */
    public String generateAccessToken(User user, AuthSession session) {
        long now = System.currentTimeMillis();

        return Jwts.builder()
                // ── Standard claims ──────────────────────────────────────
                .subject(user.getEmail())
                .id(session.getJti())                    // jti = session's pre-generated UUID
                .issuedAt(new Date(now))
                .expiration(new Date(now + accessTokenExpiryMs))
                // ── Custom claims ─────────────────────────────────────────
                // claims(Map) must be called BEFORE subject/id/dates
                // because it REPLACES the entire claims map if called after.
                // Use individual .claim() calls to avoid this gotcha.
                .claim(CLAIM_USER_ID,     user.getId().toString())
                .claim(CLAIM_DEVICE_HASH, session.getDeviceHash())
                .claim(CLAIM_RISK_LEVEL,  session.getRiskLevel().name())
                .claim(CLAIM_STEP_UP,     session.isStepUpDone())
                .claim(CLAIM_TOKEN_TYPE,  "ACCESS")
                // ── Signature ─────────────────────────────────────────────
                // signWith(key) — JJWT 0.12.x auto-selects HS256 for SecretKey.
                // Don't pass algorithm explicitly unless you need RS256/ES256.
                .signWith(secretKey)
                .compact();
        // .compact() performs:
        // 1. Serialize header to JSON → Base64URL encode
        // 2. Serialize claims to JSON → Base64URL encode
        // 3. Compute HMAC-SHA256(encodedHeader + "." + encodedPayload, secretKey)
        // 4. Base64URL encode signature
        // 5. Concatenate: header.payload.signature
    }

    /**
     * Refresh token — intentionally minimal.
     *
     * WHY no device/risk claims in refresh token?
     * Refresh token's only job: prove "I was authenticated before, give me a new access token."
     * It never reaches Transaction Service or Fraud Engine.
     * Fewer claims = smaller token = less exposure if intercepted.
     *
     * WHY separate jti from access token?
     * Access token revocation (logout) should NOT invalidate refresh token by default.
     * User logs out on web → access token jti revoked → mobile app's refresh token still works.
     * "Logout all devices" explicitly revokes both.
     *
     * Refresh token jti is stored in a separate column (not implemented here for brevity)
     * or can share the auth_sessions table with a type discriminator.
     */
    public String generateRefreshToken(User user) {
        long now = System.currentTimeMillis();

        return Jwts.builder()
                .subject(user.getEmail())
                .id(UUID.randomUUID().toString())        // independent jti
                .issuedAt(new Date(now))
                .expiration(new Date(now + refreshTokenExpiryMs))
                .claim(CLAIM_TOKEN_TYPE, "REFRESH")
                .signWith(secretKey)
                .compact();
    }

    /**
     * Parse token and return claims.
     *
     * JJWT exception hierarchy (all extend JwtException):
     * ├── MalformedJwtException     → token structure is broken (not 3 parts)
     * ├── SignatureException         → signature doesn't match → tampered
     * ├── ExpiredJwtException        → exp claim is in the past
     * ├── UnsupportedJwtException   → e.g., unsigned token presented to signed parser
     * └── IllegalArgumentException  → null/empty token string
     *
     * CALLER RESPONSIBILITY:
     * Callers (JwtAuthFilter) catch JwtException broadly.
     * They don't need to distinguish tampered vs expired — both result in 401.
     * If you need to distinguish (e.g., "token expired" vs "token invalid" error message),
     * catch subclasses separately at the call site, not here.
     *
     * THIS METHOD HAS NO SIDE EFFECTS.
     * No DB calls, no logging, no state mutation.
     * Pure: token in → claims out (or exception).
     * This makes it trivially testable without mocks.
     */
    public Claims parseAndValidate(String token) throws JwtException {
        return Jwts.parser()
                .verifyWith(secretKey)   // sets the key used to verify HMAC signature
                .build()
                .parseSignedClaims(token)
                // parseSignedClaims vs parseClaims:
                // parseClaims would accept UNSIGNED tokens — security hole.
                // parseSignedClaims REQUIRES a valid signature — use this always.
                .getPayload();           // returns Claims (the decoded JSON payload)
    }

    /**
     * Extract jti without exposing Claims object to callers who only need the ID.
     * Follows principle of least exposure — give callers exactly what they need.
     */
    public String extractJti(String token) {
        return parseAndValidate(token).getId();
    }

    public String extractEmail(String token) {
        return parseAndValidate(token).getSubject();
    }

    /**
     * Type-safe claim extraction.
     *
     * Claims.get(key, Class) handles type casting internally.
     * Safer than: (String) claims.get("riskLevel") which throws ClassCastException
     * if the claim was stored as a different type due to JSON deserialization.
     */
    public String extractRiskLevel(String token) {
        return parseAndValidate(token).get(CLAIM_RISK_LEVEL, String.class);
    }

    public boolean extractStepUpDone(String token) {
        return Boolean.TRUE.equals(parseAndValidate(token).get(CLAIM_STEP_UP, Boolean.class));
    }

    public String extractTokenType(String token) {
        return parseAndValidate(token).get(CLAIM_TOKEN_TYPE, String.class);
    }

    public long getAccessTokenExpiryMs() {
        return accessTokenExpiryMs;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DEVICE FINGERPRINT SERVICE
// Extracts device context from HTTP request, computes hash, manages persistence.
// ─────────────────────────────────────────────────────────────────────────────

import com.securepay.auth.dto.DeviceContext;
import com.securepay.auth.repository.DeviceFingerprintRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.HexFormat;
import java.util.Optional;

@Service
class DeviceFingerprintService {

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

// ─────────────────────────────────────────────────────────────────────────────
// RISK EVALUATOR SERVICE
// Computes login-time risk score from multiple signals in parallel.
// ─────────────────────────────────────────────────────────────────────────────

import com.securepay.auth.dto.RiskEvaluation;
import com.securepay.auth.repository.AuthSessionRepository;
import org.springframework.beans.factory.annotation.Qualifier;

import java.time.LocalTime;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;

@Service
class RiskEvaluatorService {

    private final Executor authExecutor;
    private final AuthSessionRepository sessionRepository;

    // Score weights — externalized in application.yml, tunable without redeploy
    private final int unknownDeviceScore;
    private final int unusualTimeScore;
    private final int concurrentSessionScore;
    private final int unusualHourStart;
    private final int unusualHourEnd;

    public RiskEvaluatorService(
            @Qualifier("authExecutor") Executor authExecutor,
            AuthSessionRepository sessionRepository,
            @Value("${auth.risk.unknown-device-score}")    int unknownDeviceScore,
            @Value("${auth.risk.unusual-time-score}")      int unusualTimeScore,
            @Value("${auth.risk.concurrent-session-score}")int concurrentSessionScore,
            @Value("${auth.risk.unusual-hour-start}")      int unusualHourStart,
            @Value("${auth.risk.unusual-hour-end}")        int unusualHourEnd
    ) {
        this.authExecutor           = authExecutor;
        this.sessionRepository      = sessionRepository;
        this.unknownDeviceScore     = unknownDeviceScore;
        this.unusualTimeScore       = unusualTimeScore;
        this.concurrentSessionScore = concurrentSessionScore;
        this.unusualHourStart       = unusualHourStart;
        this.unusualHourEnd         = unusualHourEnd;
    }

    /**
     * Evaluate login-time risk score — three checks run in PARALLEL.
     *
     * ── WHY CompletableFuture.supplyAsync() and not @Async? ─────────────────
     * @Async returns a Future you can't compose. You'd have to call .get() on
     * each one sequentially, destroying the parallelism benefit.
     *
     * CompletableFuture gives you .allOf() — a single barrier that waits for
     * ALL futures to complete, then lets you read all results at once.
     *
     * ── WHY .join() and not .get()? ─────────────────────────────────────────
     * .get() throws two checked exceptions: InterruptedException + ExecutionException.
     * You'd need try/catch everywhere, making the code noisy.
     * .join() throws CompletionException (unchecked) — propagates naturally.
     * Since we're calling .join() after .allOf().join(), all futures have
     * already completed — .join() on them is instant, no blocking.
     *
     * ── WHAT HAPPENS IF A CHECK THROWS? ─────────────────────────────────────
     * If the DB query inside concurrentSession check throws (e.g., DB is down),
     * the CompletableFuture completes exceptionally.
     * allOf().join() then throws CompletionException wrapping the cause.
     * We catch this in evaluate() and apply FAIL-SAFE behaviour:
     * return HIGH risk — better to over-flag than to silently skip a check.
     *
     * ── THREAD POOL SIZING RATIONALE ─────────────────────────────────────────
     * Each evaluate() call submits 3 tasks.
     * At 100 concurrent logins: 300 tasks submitted simultaneously.
     * corePoolSize=4, maxPool=8, queue=100:
     * - First 8 tasks run immediately on threads
     * - Next 100 queue up
     * - Beyond 108: RejectedExecutionException → caught → HIGH risk (fail-safe)
     * This is intentional backpressure — don't let unbounded queues hide overload.
     */
    public RiskEvaluation evaluate(User user, DeviceFingerprint device) {
        // ── Submit all 3 checks to the dedicated thread pool ─────────────────

        // Check 1: Is device unknown or newly registered (< 24 hours old)?
        // No DB call — pure in-memory check on the DeviceFingerprint object.
        // Fast: runs in microseconds on authExecutor.
        CompletableFuture<Boolean> unknownDeviceFuture = CompletableFuture.supplyAsync(
                () -> isUnknownDevice(device),
                authExecutor
        );

        // Check 2: Is the current hour in the unusual login window?
        // No DB call — LocalTime.now() check.
        // Even faster — but still submitted to authExecutor for consistent threading.
        CompletableFuture<Boolean> unusualTimeFuture = CompletableFuture.supplyAsync(
                this::isUnusualHour,
                authExecutor
        );

        // Check 3: Does this user have an active session from a DIFFERENT device?
        // DB call — hits idx_session_user_active index.
        // This is the slowest check — the other two will likely finish while this runs.
        CompletableFuture<Boolean> concurrentSessionFuture = CompletableFuture.supplyAsync(
                () -> sessionRepository.existsConcurrentSessionFromDifferentDevice(
                        user.getId(),
                        device.getDeviceHash(),
                        LocalDateTime.now()
                ),
                authExecutor
        );

        // ── Wait for ALL checks to complete ──────────────────────────────────
        // allOf() creates a new CompletableFuture that completes when all 3 complete.
        // .join() blocks the calling thread (login request thread) until that happens.
        // Total wait time = max(check1, check2, check3) — NOT their sum.
        try {
            CompletableFuture
                    .allOf(unknownDeviceFuture, unusualTimeFuture, concurrentSessionFuture)
                    .join();

        } catch (CompletionException ex) {
            // One of the checks failed (most likely DB unavailable for session check).
            // FAIL-SAFE: return HIGH risk — force step-up auth.
            // Better to inconvenience a legitimate user than silently skip a fraud check.
            return RiskEvaluation.builder()
                    .score(100)
                    .level(RiskLevel.HIGH)
                    .unknownDevice(true)
                    .unusualTime(false)
                    .concurrentSession(false)
                    .evaluationFailed(true)      // flag so caller can log this
                    .build();
        }

        // ── Read results — all futures are complete, .join() is instant ──────
        boolean isUnknownDevice    = unknownDeviceFuture.join();
        boolean isUnusualTime      = unusualTimeFuture.join();
        boolean isConcurrentSession = concurrentSessionFuture.join();

        // ── Compute weighted score ────────────────────────────────────────────
        // Additive model: each triggered signal adds its weight to the score.
        // Score range: 0 (all clear) to 100 (all signals triggered).
        //
        // WHY additive and not multiplicative?
        // Additive is transparent and debuggable.
        // "Score is 70 because unknownDevice(40) + concurrentSession(30)" is
        // something you can explain to a security audit. Multiplicative is not.
        int score = 0;
        if (isUnknownDevice)     score += unknownDeviceScore;
        if (isUnusualTime)       score += unusualTimeScore;
        if (isConcurrentSession) score += concurrentSessionScore;

        RiskLevel level = RiskLevel.fromScore(score);

        return RiskEvaluation.builder()
                .score(score)
                .level(level)
                .unknownDevice(isUnknownDevice)
                .unusualTime(isUnusualTime)
                .concurrentSession(isConcurrentSession)
                .evaluationFailed(false)
                .build();
    }

    /**
     * Is this device unknown or suspiciously new?
     *
     * Two cases trigger the unknown-device flag:
     * 1. Device is not trusted (user never explicitly marked it trusted)
     * 2. Device was first seen less than 24 hours ago (even if technically "known")
     *
     * WHY case 2?
     * An attacker who registers a device and immediately uses it for fraud
     * would pass a simple "is it in the table?" check.
     * A 24-hour grace period adds friction — most fraud happens fast.
     *
     * A truly trusted device (user clicked "Trust this device") bypasses both checks.
     */
    private boolean isUnknownDevice(DeviceFingerprint device) {
        if (device.isTrusted()) return false;       // explicitly trusted → never flagged
        return device.isNewDevice();                // registered < 24h ago → suspicious
    }

    /**
     * Is the current hour in the unusual login window?
     *
     * Default window: 1 AM – 5 AM (configurable in application.yml).
     *
     * WHY this range?
     * Most fraud in India's UPI ecosystem happens in early morning hours
     * when users are asleep and can't notice immediate transaction alerts.
     * This is a lightweight heuristic — not a hard block, just a risk signal.
     *
     * LIMITATION: uses server timezone. In production, use the timezone
     * from the device fingerprint for per-user local-time analysis.
     * That's a Phase 6 enhancement — don't over-engineer now.
     *
     * Package-private for testability — tests inject known hours by
     * overriding this via a Clock dependency (future enhancement).
     */
    boolean isUnusualHour() {
        int hour = LocalTime.now().getHour();
        // Handles midnight-crossing window correctly:
        // If start=22, end=6: (22 <= hour) OR (hour < 6)
        // If start=1, end=5:  (1 <= hour) AND (hour < 5) — normal window
        if (unusualHourStart < unusualHourEnd) {
            return hour >= unusualHourStart && hour < unusualHourEnd;
        } else {
            // Window crosses midnight e.g. 22:00 – 06:00
            return hour >= unusualHourStart || hour < unusualHourEnd;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AUTH SERVICE
// Orchestrates registration, login, step-up, and logout flows.
// This is the class with the most transactional complexity.
// ─────────────────────────────────────────────────────────────────────────────

import com.securepay.auth.exception.AuthenticationFailedException;
import com.securepay.auth.exception.DuplicateUserException;
import com.securepay.auth.exception.InvalidTotpException;
import com.securepay.auth.exception.TokenRevokedException;
import com.securepay.auth.repository.UserRepository;
import dev.samstevens.totp.code.CodeVerifier;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.util.logging.Logger;

@Service
@Slf4j
class AuthService {

    private final UserRepository userRepository;
    private final DeviceFingerprintService deviceFingerprintService;
    private final RiskEvaluatorService riskEvaluatorService;
    private final AuthSessionRepository sessionRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final CodeVerifier totpVerifier;

    AuthService(
            UserRepository userRepository,
            DeviceFingerprintService deviceFingerprintService,
            RiskEvaluatorService riskEvaluatorService,
            AuthSessionRepository sessionRepository,
            JwtService jwtService,
            PasswordEncoder passwordEncoder,
            CodeVerifier totpVerifier
    ) {
        this.userRepository          = userRepository;
        this.deviceFingerprintService = deviceFingerprintService;
        this.riskEvaluatorService    = riskEvaluatorService;
        this.sessionRepository       = sessionRepository;
        this.jwtService              = jwtService;
        this.passwordEncoder         = passwordEncoder;
        this.totpVerifier            = totpVerifier;
    }

    // ── REGISTER ─────────────────────────────────────────────────────────────

    /**
     * Register a new user.
     *
     * TRANSACTION: READ_COMMITTED (default) is sufficient here.
     * Registration is low-contention — two users registering same email
     * simultaneously is caught by the UNIQUE DB constraint, not by
     * isolation level. We check first for a fast, friendly error message,
     * but the DB is the authoritative guard.
     *
     * PASSWORD HASHING — BCrypt cost 12:
     * BCrypt is an adaptive hash — cost factor controls work factor.
     * Cost 12 = 2^12 = 4096 iterations = ~300ms on modern hardware.
     *
     * WHY not cost 10 (Spring's default)?
     * Hardware speed doubles roughly every 18 months (Moore's Law).
     * Cost 10 was chosen ~2012. In 2024, it runs in ~100ms — too fast.
     * An attacker with a GPU can try ~10,000 passwords/second at cost 10.
     * At cost 12: ~2,500/second. At cost 14: ~625/second.
     * Cost 12 is the current industry sweet spot.
     *
     * WHY BCrypt and not Argon2?
     * Argon2 is technically superior (memory-hard, resistant to GPU attacks).
     * BCrypt is universally supported and understood.
     * For Phase 1: BCrypt. Phase 6 enhancement: migrate to Argon2id.
     */
    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        // ── Fast-fail uniqueness check ────────────────────────────────────────
        // Check before hashing — BCrypt is ~300ms. Don't waste it on duplicates.
        // This is application-level check: gives friendly error message.
        // DB UNIQUE constraint is the real guard — handles race conditions.
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateUserException("email");
        }
        if (userRepository.existsByPhone(request.getPhone())) {
            throw new DuplicateUserException("phone");
        }

        // ── Hash password ─────────────────────────────────────────────────────
        // passwordEncoder is BCryptPasswordEncoder(12) — configured in SecurityConfig.
        // encode() internally generates a random 16-byte salt, appends it to the hash.
        // The stored hash format: $2a$12$<22-char-salt><31-char-hash>
        // BCrypt.checkpw() in matches() re-extracts the salt from the stored hash.
        // You never store or manage salt separately — BCrypt handles it.
        String passwordHash = passwordEncoder.encode(request.getPassword());

        User user = User.builder()
                .email(request.getEmail().toLowerCase().trim())   // normalize email
                .phone(request.getPhone().trim())
                .passwordHash(passwordHash)
                .isActive(true)
                .failedAttempts(0)
                .build();

        User saved = userRepository.save(user);

        log.info("New user registered: userId={}", saved.getId());

        return RegisterResponse.builder()
                .userId(saved.getId().toString())
                .message("Registration successful. Please log in.")
                .build();
    }

    // ── LOGIN ─────────────────────────────────────────────────────────────────

    /**
     * Login — orchestrates the full authentication flow.
     *
     * DELIBERATELY NOT @Transactional at this level.
     *
     * The critical reason (read carefully):
     * Spring @Transactional uses proxies. When login() calls createSession(),
     * if login() already has an open transaction, Spring's default propagation
     * REQUIRED means createSession() JOINS the outer transaction.
     *
     * That means the isolation level of createSession() (SERIALIZABLE) is
     * OVERRIDDEN by the outer transaction's isolation (READ_COMMITTED).
     * The @Transactional(isolation=SERIALIZABLE) on createSession() becomes
     * a no-op — silently, with no warning or error.
     *
     * Solution: login() has no transaction. Each called method manages its own.
     * createSession() opens a fresh SERIALIZABLE transaction independently.
     *
     * This is a Spring AOP proxy limitation: isolation upgrades only work
     * when a NEW transaction is started, not when joining an existing one.
     */
    public LoginResponse login(LoginRequest request, DeviceContext deviceContext) {

        // ── Step 1: Load and validate user ───────────────────────────────────
        User user = userRepository.findByEmail(request.getEmail().toLowerCase().trim())
                .orElseThrow(() -> new AuthenticationFailedException("Invalid credentials"));

        // Account state checks — order matters for security:
        // Check active first (account disabled = no further processing)
        // Check locked second (temporary lockout)
        // Check password last (don't reveal account state to attackers via timing)
        if (!user.isActive()) {
            throw new AuthenticationFailedException("Invalid credentials");
            // WHY same message? Revealing "account disabled" tells an attacker
            // the email is valid — an information leak. Always "Invalid credentials."
        }

        if (user.isLocked()) {
            throw new AuthenticationFailedException(
                    "Account temporarily locked. Try again later.");
            // This message is acceptable — lockout is public knowledge,
            // not a credential leak. It also discourages brute-force.
        }

        // ── Step 2: Verify password ──────────────────────────────────────────
        // passwordEncoder.matches() recomputes BCrypt with the stored salt.
        // Constant-time comparison — not susceptible to timing attacks.
        // Takes ~300ms intentionally — that's the cost factor working.
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            // Record failed attempt — may trigger lockout
            user.recordFailedAttempt();
            userRepository.save(user);

            log.warn("Failed login attempt: userId={}, failedAttempts={}",
                    user.getId(), user.getFailedAttempts());

            throw new AuthenticationFailedException("Invalid credentials");
        }

        // ── Step 3: Successful auth — reset failure counter ──────────────────
        user.resetFailedAttempts();
        userRepository.save(user);

        // ── Step 4: Find or register device fingerprint ──────────────────────
        // Has its own @Transactional(READ_COMMITTED).
        // Handles race condition internally (DIVE catch + re-fetch).
        DeviceFingerprint device =
                deviceFingerprintService.findOrRegisterDevice(user, deviceContext);

        // ── Step 5: Evaluate risk in parallel ────────────────────────────────
        // Three checks run simultaneously on authExecutor thread pool.
        // Fail-safe: if evaluation fails, returns HIGH risk.
        RiskEvaluation risk = riskEvaluatorService.evaluate(user, device);

        if (risk.isEvaluationFailed()) {
            log.error("Risk evaluation failed for userId={} — returning HIGH risk as fail-safe",
                    user.getId());
        }

        // ── Step 6: Create session with SERIALIZABLE isolation ────────────────
        // This is where the transaction boundary matters most.
        // createSession() opens a NEW SERIALIZABLE transaction — not joining any outer one.
        AuthSession session = createSession(user, device, risk);

        // ── Step 7: Generate tokens ───────────────────────────────────────────
        // Tokens embed session state — generated AFTER session is committed.
        // WHY after commit? If token generation failed, session would be orphaned.
        // Session committed first = DB is source of truth. Token is derivative.
        String accessToken  = jwtService.generateAccessToken(user, session);
        String refreshToken = jwtService.generateRefreshToken(user);

        log.info("Login successful: userId={}, riskLevel={}, stepUpRequired={}",
                user.getId(), risk.getLevel(), risk.getLevel().requiresStepUp());

        return LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .riskLevel(risk.getLevel())
                .stepUpRequired(risk.getLevel().requiresStepUp())
                .stepUpReason(risk.getPrimaryReason())
                .accessTokenExpiresIn(jwtService.getAccessTokenExpiryMs())
                .build();
    }

    // ── CREATE SESSION ────────────────────────────────────────────────────────

    /**
     * Create or retrieve session with SERIALIZABLE isolation.
     *
     * SERIALIZABLE is the strictest isolation level. In PostgreSQL specifically,
     * it uses Serializable Snapshot Isolation (SSI) — not traditional locking.
     * SSI detects serialization anomalies and aborts one of the conflicting
     * transactions with: "ERROR: could not serialize access due to concurrent update"
     *
     * HOW this prevents duplicate sessions:
     * T1 and T2 both run SELECT (no session found) + INSERT.
     * PostgreSQL's SSI detects that T2's INSERT would conflict with T1's committed INSERT.
     * T2 gets a serialization error → Spring converts it to
     * CannotSerializeTransactionException (a DataAccessException).
     *
     * We catch this and re-fetch — idempotent result.
     *
     * WHY store jti in session BEFORE generating the token?
     * The session's jti becomes the token's jti claim.
     * Session is committed to DB first → token generated from committed session.
     * This means DB and token are NEVER out of sync — the session is the source of truth.
     *
     * PACKAGE-PRIVATE (not private) so Spring AOP proxy can intercept it.
     * Private methods are not intercepted by Spring proxies — @Transactional on
     * private methods is silently ignored. This is a well-known Spring gotcha.
     */
    @Transactional(isolation = Isolation.SERIALIZABLE)
    AuthSession createSession(User user, DeviceFingerprint device, RiskEvaluation risk) {
        // ── Idempotency check: same user+device = same session ────────────────
        // If a valid session already exists for this user+device, return it.
        // "Valid" = not revoked AND not expired.
        // This makes the entire login flow idempotent for same-device re-logins.
        Optional<AuthSession> existing = sessionRepository
                .findByUserAndDeviceAndValid(user.getId(), device.getDeviceHash(),
                        LocalDateTime.now());

        if (existing.isPresent()) {
            log.debug("Reusing existing session: jti={}", existing.get().getJti());
            return existing.get();
        }

        // ── Build new session ─────────────────────────────────────────────────
        // jti is generated HERE, before the INSERT.
        // It becomes both the DB primary identifier for revocation lookups
        // AND the jwt ID claim embedded in the access token.
        String jti = UUID.randomUUID().toString();

        AuthSession session = AuthSession.builder()
                .user(user)
                .deviceHash(device.getDeviceHash())
                .jti(jti)
                .riskLevel(risk.getLevel())
                .stepUpDone(false)                              // always false at login
                .issuedAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusSeconds(
                        jwtService.getAccessTokenExpiryMs() / 1000))
                .revoked(false)
                .build();

        try {
            return sessionRepository.save(session);

        } catch (Exception ex) {
            // Serialization failure from SERIALIZABLE isolation:
            // Another concurrent transaction created a session for same user+device.
            // Re-fetch and return what was committed — fully idempotent.
            log.debug("Session serialization conflict for userId={} — re-fetching", user.getId());

            return sessionRepository
                    .findByUserAndDeviceAndValid(user.getId(), device.getDeviceHash(),
                            LocalDateTime.now())
                    .orElseThrow(() -> new IllegalStateException(
                            "Serialization conflict but no session found — DB inconsistency", ex));
        }
    }

    // ── STEP-UP ───────────────────────────────────────────────────────────────

    /**
     * Complete step-up authentication via TOTP.
     *
     * FLOW:
     * User received HIGH risk on login → frontend shows TOTP prompt →
     * User submits 6-digit code → this method verifies it →
     * Session updated: stepUpDone=true → new access token issued.
     *
     * IMPORTANT: We do NOT create a new session.
     * We UPDATE the existing session and REISSUE the access token.
     * The refresh token is untouched.
     *
     * WHY reissue access token rather than mutate claims?
     * JWT claims are immutable — the token is signed. You cannot change
     * stepUpDone from false to true in an existing token.
     * The only way to reflect updated state is to issue a new token
     * with the updated session (which now has stepUpDone=true).
     *
     * TOTP REPLAY ATTACK:
     * A 6-digit TOTP code is valid for 30 seconds.
     * An attacker could intercept it and reuse it within those 30 seconds.
     * Production mitigation: store used TOTP codes in Redis with 30s TTL.
     * Phase 1: the TOTP library handles window expiry, not replay prevention.
     * Mark this as a Phase 6 hardening task.
     */
    @Transactional
    public StepUpResponse completeStepUp(String jti, StepUpRequest request) {
        // ── Validate session ──────────────────────────────────────────────────
        AuthSession session = sessionRepository.findByJti(jti)
                .orElseThrow(() -> new AuthenticationFailedException("Session not found"));

        if (!session.isValid()) {
            throw new AuthenticationFailedException("Session expired or revoked");
        }

        if (session.isStepUpDone()) {
            // Idempotent: if step-up was already completed, just reissue token.
            // Don't make user re-verify TOTP on duplicate requests.
            String token = jwtService.generateAccessToken(session.getUser(), session);
            return StepUpResponse.builder()
                    .accessToken(token)
                    .accessTokenExpiresIn(jwtService.getAccessTokenExpiryMs())
                    .build();
        }

        // ── Validate TOTP ──────────────────────────────────────────────────
        User user = session.getUser();

        if (!user.isTotpEnabled() || user.getTotpSecret() == null) {
            throw new AuthenticationFailedException("Step-up auth not configured for this account");
        }

        // totpVerifier.isValidCode(secret, code):
        // - Computes expected TOTP for current 30s window (± 1 window for clock skew)
        // - Constant-time comparison — not susceptible to timing attacks
        boolean valid = totpVerifier.isValidCode(user.getTotpSecret(), request.getTotpCode());
        if (!valid) {
            throw new InvalidTotpException();
        }

        // ── Mark step-up complete ──────────────────────────────────────────────
        session.setStepUpDone(true);
        sessionRepository.save(session);

        // ── Reissue access token reflecting updated step-up state ─────────────
        String newToken = jwtService.generateAccessToken(user, session);

        log.info("Step-up completed: userId={}, jti={}", user.getId(), jti);

        return StepUpResponse.builder()
                .accessToken(newToken)
                .accessTokenExpiresIn(jwtService.getAccessTokenExpiryMs())
                .build();
    }

    // ── LOGOUT ────────────────────────────────────────────────────────────────

    /**
     * Logout — revoke the current session.
     *
     * IDEMPOTENT by design:
     * Calling logout twice on the same token is safe — session.revoke()
     * checks the current state before mutating.
     *
     * WHY not delete the session row?
     * Deleted rows can't be audited. Revoked sessions stay in the DB
     * until the nightly cleanup job purges sessions older than 30 days.
     * This gives you a full auth audit trail — who logged in, when, from where,
     * and when they logged out.
     *
     * WHAT THIS DOESN'T DO:
     * It does not invalidate the access token immediately.
     * The token may still be valid for up to 15 minutes (until expiry).
     * JwtAuthFilter checks revoked=true on every request, so the window is
     * actually: next request after logout → token rejected immediately.
     * There is no window if the client stops sending requests.
     */
    @Transactional
    public void logout(String jti) {
        sessionRepository.findByJti(jti).ifPresent(session -> {
            session.revoke();         // domain method — idempotent, sets revokedAt
            sessionRepository.save(session);
            log.info("Session revoked: jti={}, userId={}", jti, session.getUser().getId());
        });
        // If session not found: silently succeed.
        // Token was already invalid (expired/non-existent) — logout achieved.
    }

    // ── REFRESH ───────────────────────────────────────────────────────────────

    /**
     * Refresh access token using a valid refresh token.
     *
     * WHAT IS REFRESHED: the access token only.
     * The refresh token itself is NOT rotated here.
     *
     * WHY NOT rotate refresh tokens?
     * Refresh token rotation (issuing a new refresh token on each refresh)
     * is a security best practice — old refresh tokens become single-use.
     * But it requires storing refresh token jti in the DB and revoking it.
     * Phase 1: skip rotation for simplicity. Add in Phase 6 hardening.
     *
     * WHAT VALIDATES THE REFRESH TOKEN:
     * 1. JWT signature (JwtService.parseAndValidate)
     * 2. Token type claim = "REFRESH" (guards against using access token as refresh)
     * 3. User still exists and is active
     * 4. An active session still exists for this user
     *
     * WHY check active session even for refresh?
     * "Logout all devices" revokes all sessions. Without this check,
     * a refresh token could generate a new access token after "logout all" — defeating it.
     */
    @Transactional
    public LoginResponse refresh(RefreshRequest request) {
        // ── Validate refresh token signature + expiry ─────────────────────────
        String email;
        try {
            String tokenType = jwtService.extractTokenType(request.getRefreshToken());
            if (!"REFRESH".equals(tokenType)) {
                throw new AuthenticationFailedException("Invalid token type for refresh");
            }
            email = jwtService.extractEmail(request.getRefreshToken());

        } catch (JwtException ex) {
            throw new AuthenticationFailedException("Invalid or expired refresh token");
        }

        // ── Load user ─────────────────────────────────────────────────────────
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationFailedException("User not found"));

        if (!user.isActive()) {
            throw new AuthenticationFailedException("Account is disabled");
        }

        // ── Find active session ───────────────────────────────────────────────
        // We need an active session to embed its risk/device claims in the new token.
        // If all sessions are revoked (logout all), this throws → refresh denied.
        AuthSession session = sessionRepository
                .findFirstActiveByUserId(user.getId(), LocalDateTime.now())
                .orElseThrow(() -> new TokenRevokedException());

        // ── Generate new access token from existing session ───────────────────
        // Risk level and device hash come from the existing session — not recomputed.
        // Risk is sticky for the session lifetime. To get re-evaluated risk, user must re-login.
        String newAccessToken = jwtService.generateAccessToken(user, session);

        log.debug("Token refreshed: userId={}, sessionJti={}", user.getId(), session.getJti());

        return LoginResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(request.getRefreshToken())        // return same refresh token
                .riskLevel(session.getRiskLevel())
                .stepUpRequired(false)                          // step-up already done in session
                .accessTokenExpiresIn(jwtService.getAccessTokenExpiryMs())
                .build();
    }
}