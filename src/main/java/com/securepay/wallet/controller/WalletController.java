package com.securepay.wallet.controller;

import com.securepay.auth.filter.JwtAuthFilter;
import com.securepay.auth.model.RiskLevel;
import com.securepay.transaction.exception.InsufficientFundsException;
import com.securepay.transaction.service.AuthContext;
import com.securepay.transaction.service.WalletFundsService;
import com.securepay.transaction.service.WalletFundsService.WalletBalanceView;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/wallet")
public class WalletController {

    private final WalletFundsService walletFundsService;

    public WalletController(WalletFundsService walletFundsService) {
        this.walletFundsService = walletFundsService;
    }

    @GetMapping("/balance")
    public ResponseEntity<WalletBalanceView> balance(HttpServletRequest request) {
        AuthContext auth = requireAuthContext(request);
        return ResponseEntity.ok(walletFundsService.getBalance(auth.getUserId()));
    }

    @PostMapping("/add")
    public ResponseEntity<WalletBalanceView> add(
            @Valid @RequestBody AmountRequest body,
            HttpServletRequest request
    ) {
        AuthContext auth = requireAuthContext(request);
        return ResponseEntity.ok(walletFundsService.addFunds(auth.getUserId(), body.amount()));
    }

    @PostMapping("/withdraw")
    public ResponseEntity<WalletBalanceView> withdraw(
            @Valid @RequestBody AmountRequest body,
            HttpServletRequest request
    ) throws InsufficientFundsException {
        AuthContext auth = requireAuthContext(request);
        return ResponseEntity.ok(walletFundsService.withdraw(auth.getUserId(), body.amount()));
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

    public record AmountRequest(
            @NotNull @DecimalMin(value = "0.01", inclusive = true) BigDecimal amount
    ) {}
}
