package com.securepay.auth.service;

import com.securepay.auth.model.AuthSession;
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
import java.util.UUID;

@Service
public class JwtService {

    public static final String CLAIM_USER_ID = "userId";
    public static final String CLAIM_DEVICE_HASH = "deviceHash";
    public static final String CLAIM_RISK_LEVEL = "riskLevel";
    public static final String CLAIM_STEP_UP = "stepUpDone";
    public static final String CLAIM_TOKEN_TYPE = "tokenType";

    private final SecretKey secretKey;
    private final long accessTokenExpiryMs;
    private final long refreshTokenExpiryMs;

    public JwtService(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.access-token-expiry-ms}") long accessTokenExpiryMs,
            @Value("${jwt.refresh-token-expiry-ms}") long refreshTokenExpiryMs
    ) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpiryMs = accessTokenExpiryMs;
        this.refreshTokenExpiryMs = refreshTokenExpiryMs;
    }

    public String generateAccessToken(User user, AuthSession session) {
        long now = System.currentTimeMillis();

        return Jwts.builder()
                .subject(user.getEmail())
                .id(session.getJti())
                .issuedAt(new Date(now))
                .expiration(new Date(now + accessTokenExpiryMs))
                .claim(CLAIM_USER_ID, user.getId().toString())
                .claim(CLAIM_DEVICE_HASH, session.getDeviceHash())
                .claim(CLAIM_RISK_LEVEL, session.getRiskLevel().name())
                .claim(CLAIM_STEP_UP, session.isStepUpDone())
                .claim(CLAIM_TOKEN_TYPE, "ACCESS")
                .signWith(secretKey)
                .compact();
    }

    public String generateRefreshToken(User user) {
        long now = System.currentTimeMillis();

        return Jwts.builder()
                .subject(user.getEmail())
                .id(UUID.randomUUID().toString())
                .issuedAt(new Date(now))
                .expiration(new Date(now + refreshTokenExpiryMs))
                .claim(CLAIM_TOKEN_TYPE, "REFRESH")
                .signWith(secretKey)
                .compact();
    }

    public Claims parseAndValidate(String token) throws JwtException {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractJti(String token) {
        return parseAndValidate(token).getId();
    }

    public String extractEmail(String token) {
        return parseAndValidate(token).getSubject();
    }

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
