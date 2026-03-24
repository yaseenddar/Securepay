package com.securepay.app.auth.config;

// ─────────────────────────────────────────────────────────────────────────────
// SECURITY CONFIG
// Wires Spring Security filter chain.
// This is the most misunderstood class in Spring Boot security.
// ─────────────────────────────────────────────────────────────────────────────

import com.securepay.app.auth.filter.JwtAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

importcom.securepay.app.auth.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final UserRepository userRepository;

    SecurityConfig(JwtAuthFilter jwtAuthFilter, UserRepository userRepository) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.userRepository = userRepository;
    }

    /**
     * Core filter chain configuration.
     *
     * WHAT HAPPENS INTERNALLY when a request comes in:
     * 1. Request enters the filter chain (ordered list of filters)
     * 2. JwtAuthFilter runs before UsernamePasswordAuthenticationFilter
     * 3. JwtAuthFilter extracts token, validates, sets SecurityContext
     * 4. Then the request reaches the controller
     *
     * WHY STATELESS session?
     * We're using JWTs — the server never stores session state in HTTP session.
     * SessionCreationPolicy.STATELESS tells Spring: never create HttpSession.
     * Without this, Spring might still create a session "just in case" — wasteful.
     *
     * WHY disable CSRF?
     * CSRF attacks exploit cookies. We use Authorization header (Bearer token).
     * Bearer tokens are not automatically sent by browsers → CSRF is not applicable.
     * Enabling CSRF with JWT would add complexity with zero security benefit.
     */
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/api/v1/auth/register",
                                "/api/v1/auth/login",
                                "/api/v1/auth/refresh",
                                "/actuator/health"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    /**
     * UserDetailsService — loads user from DB by email for Spring Security.
     *
     * Called by JwtAuthFilter on every authenticated request.
     * Also used internally by Spring Security for its own auth mechanisms.
     *
     * WHY load from DB on every request and not trust JWT claims?
     * The JWT 'sub' claim is the email at token-issuance time.
     * Between issuance and now, the user could be:
     * - Disabled (account suspended)
     * - Have roles changed (permissions updated)
     * JWT claims are a snapshot — DB is the live truth.
     *
     * PERFORMANCE NOTE:
     * This is called on every authenticated request.
     * Phase 6: wrap with @Cacheable(ttl=30s) to reduce DB load.
     * For now, one SELECT per request — acceptable for Phase 1.
     */
    @Bean
    UserDetailsService userDetailsService() {
        return email -> {
           com.securepay.app.auth.model.User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException(
                            "User not found: " + email));

            // Spring Security's built-in User builder
            // Maps our domain User to Spring's UserDetails contract
            return org.springframework.security.core.userdetails.User.builder()
                    .username(user.getEmail())
                    .password(user.getPasswordHash())
                    .disabled(!user.isActive())
                    .accountLocked(user.isLocked())
                    // Roles will be added in Phase 6 (RBAC)
                    // For now: all authenticated users have USER authority
                    .roles("USER")
                    .build();
        };
    }

    /**
     * TOTP code verifier bean — used by AuthService.completeStepUp().
     * The TOTP library handles:
     * - Time window computation (current 30s window ± 1 for clock skew)
     * - HMAC-SHA1 computation (RFC 6238)
     * - Constant-time comparison (no timing attacks)
     */
    @Bean
    dev.samstevens.totp.code.CodeVerifier totpVerifier() {
        dev.samstevens.totp.code.DefaultCodeGenerator generator =
                new dev.samstevens.totp.code.DefaultCodeGenerator();
        return new dev.samstevens.totp.code.DefaultCodeVerifier(
                generator,
                new dev.samstevens.totp.time.SystemTimeProvider()
        );
    }
     * ~300ms on modern hardware — fast enough for UX, slow enough to defeat brute force.
     * Each +1 cost doubles the time. Choose based on your hardware benchmark.
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * AuthenticationManager needed if you want to use
     * Spring's built-in authenticate() method (optional here,
     * but good practice to expose it).
     */
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ASYNC EXECUTOR CONFIG
// Custom thread pool for parallel risk evaluation.
// ─────────────────────────────────────────────────────────────────────────────

import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.util.concurrent.*;

@Configuration
@EnableAsync
@EnableScheduling
class AsyncConfig {

    @Value("${auth.executor.core-pool-size}") private int corePoolSize;
    @Value("${auth.executor.max-pool-size}")  private int maxPoolSize;
    @Value("${auth.executor.queue-capacity}") private int queueCapacity;

    /**
     * Dedicated thread pool for auth risk evaluation.
     *
     * DESIGN DECISIONS explained:
     *
     * corePoolSize=4: always-alive threads. Handles normal load without
     *   thread creation overhead on each request.
     *
     * maxPoolSize=8: burst capacity. Extra threads created when queue fills.
     *   Threads above core are killed after keepAliveTime if idle.
     *
     * LinkedBlockingQueue(100): BOUNDED queue — critical.
     *   Unbounded queue = infinite backlog under load = OOM.
     *   When queue is full + threads at max, RejectedExecutionHandler fires.
     *   Default handler (AbortPolicy) throws RejectedExecutionException —
     *   you catch this and return a conservative HIGH risk score (fail safe).
     *
     * Thread naming ("auth-risk-%d"): makes thread dumps readable.
     *   "auth-risk-3 blocked on DB query" is far more useful than "pool-2-thread-3".
     *
     * prestartAllCoreThreads(): create core threads at startup, not lazily.
     *   First requests after startup don't pay thread creation cost.
     */
    @Bean("authExecutor")
    Executor authExecutor() {
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
                corePoolSize,
                maxPoolSize,
                60L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(queueCapacity),
                new ThreadFactory() {
                    private int count = 0;
                    @Override
                    public Thread newThread(Runnable r) {
                        Thread t = new Thread(r);
                        t.setName("auth-risk-" + count++);
                        t.setDaemon(true); // don't block JVM shutdown
                        return t;
                    }
                },
                new ThreadPoolExecutor.AbortPolicy() // explicit — don't swallow rejections silently
        );
        executor.prestartAllCoreThreads();
        return executor;
    }
}
