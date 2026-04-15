package com.securepay.auth.service;

import com.securepay.auth.exception.AuthenticationFailedException;
import com.securepay.auth.exception.DuplicateUserException;
import com.securepay.auth.exception.InvalidTotpException;
import com.securepay.auth.exception.TokenRevokedException;
import com.securepay.auth.model.AuthSession;
import com.securepay.auth.model.DeviceFingerprint;
import com.securepay.auth.model.User;
import com.securepay.auth.repository.AuthSessionRepository;
import com.securepay.auth.repository.UserRepository;
import com.securepay.transaction.model.Wallet;
import com.securepay.transaction.repository.WalletRepository;

import dev.samstevens.totp.code.CodeVerifier;
import io.jsonwebtoken.JwtException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import securepay.app.auth.dto.DeviceContext;
import securepay.app.auth.dto.LoginRequest;
import securepay.app.auth.dto.LoginResponse;
import securepay.app.auth.dto.RefreshRequest;
import securepay.app.auth.dto.RegisterRequest;
import securepay.app.auth.dto.RegisterResponse;
import securepay.app.auth.dto.RiskEvaluation;
import securepay.app.auth.dto.StepUpRequest;
import securepay.app.auth.dto.StepUpResponse;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final DeviceFingerprintService deviceFingerprintService;
    private final RiskEvaluatorService riskEvaluatorService;
    private final AuthSessionRepository sessionRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final CodeVerifier totpVerifier;
    private final WalletRepository walletRepository;

    public AuthService(
            UserRepository userRepository,
            DeviceFingerprintService deviceFingerprintService,
            RiskEvaluatorService riskEvaluatorService,
            AuthSessionRepository sessionRepository,
            JwtService jwtService,
            PasswordEncoder passwordEncoder,
            CodeVerifier totpVerifier,
            WalletRepository walletRepository
    ) {
        this.userRepository = userRepository;
        this.deviceFingerprintService = deviceFingerprintService;
        this.riskEvaluatorService = riskEvaluatorService;
        this.sessionRepository = sessionRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.totpVerifier = totpVerifier;
        this.walletRepository= walletRepository;
    }

    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new DuplicateUserException("email");
        }
        if (userRepository.existsByPhone(request.getPhone())) {
            throw new DuplicateUserException("phone");
        }

        String passwordHash = passwordEncoder.encode(request.getPassword());

        User user = User.builder()
                .email(request.getEmail().toLowerCase().trim())
                .phone(request.getPhone().trim())
                .passwordHash(passwordHash)
                .isActive(true)
                .failedAttempts(0)
                .build();

        User saved = userRepository.save(user);

        log.info("New user registered: userId={}", saved.getId());
        Wallet wallet = Wallet.builder()
                .userId(saved.getId())
                .balance(new BigDecimal(5000))
                .payeeVpa(saved.getVpa())
                .build();

        walletRepository.save(wallet);
        log.info("Automatic user Wallet registered: userId={}", wallet.getId());
        return RegisterResponse.builder()
                .userId(saved.getId().toString())
                .message("Registration successful. Please log in.")
                .build();
    }

    public LoginResponse login(LoginRequest request, DeviceContext deviceContext) {
    	log.info("User Login Info {} and device info {}", request,deviceContext);

        User user = userRepository.findByEmail(request.getEmail().toLowerCase().trim())
                .orElseThrow(() -> new AuthenticationFailedException("Invalid credentials"));

        if (!user.isActive()) {
            throw new AuthenticationFailedException("Invalid credentials");
        }
        
        // fall back early if attmpts > 5 and user still is locked
        if (user.isLocked()) {
            throw new AuthenticationFailedException(
                    "Account temporarily locked. Try again later.");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            user.recordFailedAttempt();
            userRepository.save(user);

            log.warn("Failed login attempt: userId={}, failedAttempts={}",
                    user.getId(), user.getFailedAttempts());

            throw new AuthenticationFailedException("Invalid credentials");
        }
        // update the login failed attempt to 0 in db if successsfull login
        user.resetFailedAttempts();
        
        userRepository.save(user);

        DeviceFingerprint device =
                deviceFingerprintService.findOrRegisterDevice(user, deviceContext);

        RiskEvaluation risk = riskEvaluatorService.evaluate(user, device);

        if (risk.isEvaluationFailed()) {
            log.error("Risk evaluation failed for userId={} — returning HIGH risk as fail-safe",
                    user.getId());
        }

        AuthSession session = createSession(user, device, risk);

        String accessToken = jwtService.generateAccessToken(user, session);
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

    @Transactional(isolation = Isolation.SERIALIZABLE)
    AuthSession createSession(User user, DeviceFingerprint device, RiskEvaluation risk) {
        Optional<AuthSession> existing = sessionRepository
                .findFirstByUser_IdAndDeviceHashAndRevokedFalseAndExpiresAtAfterOrderByIssuedAtDesc(
                        user.getId(), device.getDeviceHash(), LocalDateTime.now());

        if (existing.isPresent()) {
            log.debug("Reusing existing session: jti={}", existing.get().getJti());
            return existing.get();
        }

        String jti = UUID.randomUUID().toString();

        AuthSession session = AuthSession.builder()
                .user(user)
                .deviceHash(device.getDeviceHash())
                .jti(jti)
                .riskLevel(risk.getLevel())
                .stepUpDone(false)
                .issuedAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusSeconds(
                        jwtService.getAccessTokenExpiryMs() / 1000))
                .revoked(false)
                .build();

        try {
            return sessionRepository.save(session);

        } catch (Exception ex) {
            log.debug("Session serialization conflict for userId={} — re-fetching", user.getId());

            return sessionRepository
                    .findFirstByUser_IdAndDeviceHashAndRevokedFalseAndExpiresAtAfterOrderByIssuedAtDesc(
                            user.getId(), device.getDeviceHash(), LocalDateTime.now())
                    .orElseThrow(() -> new IllegalStateException(
                            "Serialization conflict but no session found — DB inconsistency", ex));
        }
    }

    @Transactional
    public StepUpResponse completeStepUp(String jti, StepUpRequest request) {
        AuthSession session = sessionRepository.findByJti(jti)
                .orElseThrow(() -> new AuthenticationFailedException("Session not found"));

        if (!session.isValid()) {
            throw new AuthenticationFailedException("Session expired or revoked");
        }

        if (session.isStepUpDone()) {
            String token = jwtService.generateAccessToken(session.getUser(), session);
            return StepUpResponse.builder()
                    .accessToken(token)
                    .accessTokenExpiresIn(jwtService.getAccessTokenExpiryMs())
                    .build();
        }

        User user = session.getUser();

        if (!user.isTotpEnabled() || user.getTotpSecret() == null) {
            throw new AuthenticationFailedException("Step-up auth not configured for this account");
        }

        boolean valid = totpVerifier.isValidCode(user.getTotpSecret(), request.getTotpCode());
        if (!valid) {
            throw new InvalidTotpException();
        }

        session.setStepUpDone(true);
        sessionRepository.save(session);

        String newToken = jwtService.generateAccessToken(user, session);

        log.info("Step-up completed: userId={}, jti={}", user.getId(), jti);

        return StepUpResponse.builder()
                .accessToken(newToken)
                .accessTokenExpiresIn(jwtService.getAccessTokenExpiryMs())
                .build();
    }

    @Transactional
    public void logout(String jti) {
        sessionRepository.findByJti(jti).ifPresent(session -> {
            session.revoke();
            sessionRepository.save(session);
            log.info("Session revoked: jti={}, userId={}", jti, session.getUser().getId());
        });
    }

    @Transactional
    public LoginResponse refresh(RefreshRequest request) {
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

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthenticationFailedException("User not found"));

        if (!user.isActive()) {
            throw new AuthenticationFailedException("Account is disabled");
        }

        AuthSession session = sessionRepository
                .findFirstByUser_IdAndRevokedFalseAndExpiresAtAfterOrderByIssuedAtDesc(
                        user.getId(), LocalDateTime.now())
                .orElseThrow(TokenRevokedException::new);

        String newAccessToken = jwtService.generateAccessToken(user, session);

        log.debug("Token refreshed: userId={}, sessionJti={}", user.getId(), session.getJti());

        return LoginResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(request.getRefreshToken())
                .riskLevel(session.getRiskLevel())
                .stepUpRequired(false)
                .accessTokenExpiresIn(jwtService.getAccessTokenExpiryMs())
                .build();
    }
}
