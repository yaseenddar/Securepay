package com.securepay.auth.filter;

import com.securepay.auth.model.AuthSession;
import com.securepay.auth.repository.AuthSessionRepository;
import com.securepay.auth.service.JwtService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * JWT Authentication Filter.
 *
 * POSITION IN FILTER CHAIN:
 * Inserted BEFORE UsernamePasswordAuthenticationFilter (see SecurityConfig).
 * Runs on every request — authenticated or not.
 * Public endpoints (/register, /login) pass through without a token,
 * the filter skips them cleanly (no Authorization header → early return).
 *
 * THE "DO NOT THROW" CONTRACT:
 * This filter MUST NOT throw exceptions for invalid tokens.
 * Why? If it throws, the exception bubbles up to the container,
 * bypassing Spring Security's ExceptionTranslationFilter entirely.
 * The user gets a raw 500, not a clean 401.
 *
 * Correct pattern: on any failure, call filterChain.doFilter() and return.
 * SecurityContext remains empty → ExceptionTranslationFilter sees
 * unauthenticated request → returns 401 with proper JSON body.
 *
 * THE "CHECK AUTHENTICATION IS NULL" GUARD:
 * SecurityContextHolder is thread-local but one JVM thread can handle
 * multiple requests under async dispatch. Checking getAuthentication() == null
 * before setting prevents overwriting a valid auth set by a prior filter.
 *
 * PERFORMANCE:
 * Two operations run on every authenticated request:
 * 1. JwtService.parseAndValidate() — pure CPU, ~1ms
 * 2. sessionRepository.findByJti()  — DB hit, ~5ms with index
 * Total overhead per request: ~6ms. Acceptable for an auth service.
 * Redis cache for jti → 0.1ms — add this in Phase 6.
 */
@Component
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {

    // Request attribute keys — used by controllers to read claims
    // String constants prevent silent typos ("jti" vs "JWT_ID")
    public static final String ATTR_JTI        = "jti";
    public static final String ATTR_RISK_LEVEL = "riskLevel";
    public static final String ATTR_STEP_UP    = "stepUpDone";
    public static final String ATTR_USER_ID    = "userId";

    private final JwtService jwtService;
    private final AuthSessionRepository sessionRepository;
    private final UserDetailsService userDetailsService;

    public JwtAuthFilter(
            JwtService jwtService,
            AuthSessionRepository sessionRepository,
            UserDetailsService userDetailsService
    ) {
        this.jwtService = jwtService;
        this.sessionRepository = sessionRepository;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // ── Step 1: Extract Bearer token ─────────────────────────────────────
        // Authorization: Bearer <token>
        // If header is absent or malformed → pass through (unauthenticated).
        // Public endpoints hit this path — they have no Authorization header.
        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // No token present — not an error, just unauthenticated.
            // Public endpoints (/login, /register) legitimately have no token.
            filterChain.doFilter(request, response);
            return;
        }

        // substring(7) strips "Bearer " prefix (7 characters including the space)
        String token = authHeader.substring(7);

        if (token.isBlank()) {
            // "Bearer " with nothing after it — malformed, treat as unauthenticated
            filterChain.doFilter(request, response);
            return;
        }

        // ── Step 2: Validate JWT signature + expiry (no DB) ──────────────────
        // parseAndValidate() verifies:
        //   - HMAC-SHA256 signature matches our secret key
        //   - 'exp' claim has not passed
        //   - Token is structurally valid (3 Base64URL parts)
        //
        // This step has NO database interaction — pure cryptographic verification.
        // Fast: ~1ms. Runs before the DB hit to short-circuit invalid tokens cheaply.
        //
        // On failure: JwtException thrown (expired, tampered, malformed).
        // We catch broadly — all failures mean "don't authenticate."
        Claims claims;
        try {
            claims = jwtService.parseAndValidate(token);
        } catch (JwtException ex) {
            // Log at DEBUG — expired tokens are normal (not an attack).
            // Log at WARN only if signature is invalid (potential tampering).
            if (ex.getMessage() != null && ex.getMessage().contains("signature")) {
                log.warn("JWT signature validation failed — possible token tampering: {}",
                        ex.getMessage());
            } else {
                log.debug("JWT validation failed (likely expired): {}", ex.getMessage());
            }
            filterChain.doFilter(request, response);
            return;
        }

        // ── Step 3: Token type guard ──────────────────────────────────────────
        // Reject refresh tokens presented as access tokens.
        // Without this check, a user could use their refresh token to access
        // protected endpoints — defeating the purpose of short-lived access tokens.
        String tokenType = claims.get(JwtService.CLAIM_TOKEN_TYPE, String.class);
        if (!"ACCESS".equals(tokenType)) {
            log.warn("Non-access token presented to auth filter: type={}", tokenType);
            filterChain.doFilter(request, response);
            return;
        }

        // ── Step 4: Revocation check (DB lookup by jti) ───────────────────────
        // JWT is cryptographically valid but may have been explicitly revoked
        // (user logged out, account compromised, "logout all devices").
        //
        // jti (JWT ID) is a unique identifier per token, stored in auth_sessions.
        // findByJti() hits the idx_session_jti unique index — O(log n).
        //
        // Three outcomes:
        // a) Session found + valid (not revoked, not expired) → proceed
        // b) Session found + revoked → reject
        // c) Session not found → reject (treat as revoked — defense in depth)
        String jti = claims.getId();
        Optional<AuthSession> sessionOpt = sessionRepository.findByJti(jti);

        if (sessionOpt.isEmpty() || !sessionOpt.get().isValid()) {
            log.debug("JTI not found or revoked: jti={}", jti);
            filterChain.doFilter(request, response);
            return;
        }

        // ── Step 5: Set SecurityContext ───────────────────────────────────────
        // Only if context is not already set — prevents overwriting valid auth.
        // getAuthentication() == null means no filter before us authenticated this request.
        String email = claims.getSubject();

        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // loadUserByUsername() hits the DB to load UserDetails (roles, enabled status).
            // WHY load from DB and not trust JWT claims?
            // - User could be disabled after token was issued
            // - Roles could have changed (user promoted/demoted)
            // - JWT claims are stale — DB is always current
            //
            // Tradeoff: one extra DB query per request.
            // Mitigation: UserDetailsService implementations are cache-friendly.
            // In Phase 6: add a short-TTL cache (30s) here.
            UserDetails userDetails;
            try {
                userDetails = userDetailsService.loadUserByUsername(email);
            } catch (Exception ex) {
                // User deleted or DB unavailable — don't authenticate
                log.warn("Failed to load UserDetails for email={}: {}", email, ex.getMessage());
                filterChain.doFilter(request, response);
                return;
            }

            // UsernamePasswordAuthenticationToken(principal, credentials, authorities)
            // credentials = null: we never store or pass the password after initial auth.
            // Once authenticated, credentials are cleared — this is a Spring Security best practice.
            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,                           // credentials cleared post-auth
                            userDetails.getAuthorities()    // roles/permissions
                    );

            // WebAuthenticationDetails adds request metadata to the Authentication object:
            // remote IP address and session ID (if any).
            // Useful for audit logging in Spring Security events.
            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            // Set in SecurityContext — all downstream code can now call:
            // SecurityContextHolder.getContext().getAuthentication()
            // to get the authenticated user.
            SecurityContextHolder.getContext().setAuthentication(authToken);
        }

        // ── Step 6: Attach JWT claims as request attributes ───────────────────
        // Controllers and downstream services read these via:
        //   String jti = (String) request.getAttribute(JwtAuthFilter.ATTR_JTI);
        //
        // WHY attributes and not just re-parse the token in the controller?
        // The token has already been parsed and validated here.
        // Re-parsing in the controller would be duplicate work (another DB hit for jti,
        // another signature verification). Attributes are the parsed, validated result.
        //
        // WHY not put these in SecurityContext?
        // SecurityContext holds Authentication (identity + authorities).
        // JWT-specific claims (riskLevel, stepUpDone) are not Spring Security concepts.
        // Mixing them would couple our business logic to Spring Security internals.
        // Request attributes are the clean separation point.
        request.setAttribute(ATTR_JTI, jti);
        request.setAttribute(ATTR_USER_ID,
                claims.get(JwtService.CLAIM_USER_ID, String.class));
        request.setAttribute(ATTR_RISK_LEVEL,
                claims.get(JwtService.CLAIM_RISK_LEVEL, String.class));
        request.setAttribute(ATTR_STEP_UP,
                claims.get(JwtService.CLAIM_STEP_UP, Boolean.class));

        // ── Continue filter chain ─────────────────────────────────────────────
        // Request proceeds to the next filter, then eventually to the controller.
        // SecurityContext is now populated — Spring Security allows the request.
        filterChain.doFilter(request, response);
    }
}