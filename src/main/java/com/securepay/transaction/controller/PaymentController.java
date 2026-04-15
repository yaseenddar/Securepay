package com.securepay.transaction.controller;

import com.securepay.auth.filter.JwtAuthFilter;
import com.securepay.auth.model.RiskLevel;
import com.securepay.transaction.dto.PaymentRequest;
import com.securepay.transaction.dto.PaymentResponse;
import com.securepay.transaction.exception.InsufficientFundsException;
import com.securepay.transaction.service.AuthContext;
import com.securepay.transaction.service.PaymentOperations;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.util.UUID;

/**
 * Payment HTTP API — delegates to {@link PaymentOperations}.
 * Caller identity and risk signals come from the JWT (see {@link JwtAuthFilter}).
 */
@RestController
@RequestMapping("/api/v1/payment")
public class PaymentController {

    private final PaymentOperations paymentOperations;

    public PaymentController(PaymentOperations paymentOperations) {
        this.paymentOperations = paymentOperations;
    }

    /**
     * Initiate (and when allowed, complete) a payment. Idempotent on {@code idempotencyKey}.
     */
    @PostMapping
    public ResponseEntity<PaymentResponse> initiate(
            @Valid @RequestBody InitiatePaymentRequest body,
            HttpServletRequest request
    ) throws InsufficientFundsException {
        AuthContext auth = requireAuthContext(request);
        PaymentRequest paymentRequest = PaymentRequest.builder()
                .idempotencyKey(body.idempotencyKey())
                .payeeVpa(body.payeeVpa())
                .amount(body.amount())
                .build();
        return ResponseEntity.ok(paymentOperations.initiatePayment(paymentRequest, auth));
    }

    @GetMapping("/{paymentId}")
    public ResponseEntity<PaymentResponse> get(
            @PathVariable UUID paymentId,
            HttpServletRequest request
    ) {
        AuthContext auth = requireAuthContext(request);
        return ResponseEntity.ok(paymentOperations.getPayment(paymentId, auth));
    }

    /**
     * Reverse a successful payment initiated by the authenticated payer.
     */
    @PostMapping("/{paymentId}/reverse")
    public ResponseEntity<PaymentResponse> reverse(
            @PathVariable UUID paymentId,
            @Valid @RequestBody(required = false) ReversePaymentRequest body,
            HttpServletRequest request
    ) throws InsufficientFundsException {
        AuthContext auth = requireAuthContext(request);
        String reason = body != null && body.reason() != null ? body.reason() : "Reversal requested by payer";
        return ResponseEntity.ok(paymentOperations.reversePayment(paymentId, reason, auth));
    }

    private static AuthContext requireAuthContext(HttpServletRequest request) {
        String userIdRaw = (String) request.getAttribute(JwtAuthFilter.ATTR_USER_ID);
        if (userIdRaw == null || userIdRaw.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        UUID userId;
        try {
            userId = UUID.fromString(userIdRaw.trim());
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        RiskLevel riskLevel = parseRiskLevel((String) request.getAttribute(JwtAuthFilter.ATTR_RISK_LEVEL));
        Boolean stepUpClaim = (Boolean) request.getAttribute(JwtAuthFilter.ATTR_STEP_UP);
        boolean stepUpDone = Boolean.TRUE.equals(stepUpClaim);
        String deviceHash = (String) request.getAttribute(JwtAuthFilter.ATTR_DEVICE_HASH);

        return new AuthContext(userId, riskLevel, stepUpDone, deviceHash);
    }

    private static RiskLevel parseRiskLevel(String raw) {
        if (raw == null || raw.isBlank()) {
            return RiskLevel.MEDIUM;
        }
        try {
            return RiskLevel.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            return RiskLevel.MEDIUM;
        }
    }

    public record InitiatePaymentRequest(
            @NotBlank @Size(max = 64) String idempotencyKey,
            @NotBlank @Size(max = 100) String payeeVpa,
            @NotNull @DecimalMin(value = "0.01", inclusive = true) BigDecimal amount
    ) {}

    public record ReversePaymentRequest(
            @Size(max = 500) String reason
    ) {}
}
