package com.securepay.transaction.service;

import com.securepay.debug.DebugNdjson619;
import com.securepay.transaction.exception.InsufficientFundsException;
import com.securepay.transaction.exception.WalletNotFoundException;
import com.securepay.transaction.model.Wallet;
import com.securepay.transaction.repository.WalletRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.UUID;

/**
 * Authenticated user's wallet: read balance, add funds, withdraw.
 */
@Service
@Slf4j
public class WalletFundsService {

    private final WalletRepository walletRepository;
    private final LedgerService ledgerService;

    public WalletFundsService(WalletRepository walletRepository, LedgerService ledgerService) {
        this.walletRepository = walletRepository;
        this.ledgerService = ledgerService;
    }

    @Transactional(readOnly = true)
    public WalletBalanceView getBalance(UUID userId) {
        Wallet wallet = walletRepository.findByUserId(userId)
                .orElseThrow(() -> new WalletNotFoundException("Wallet not found for user"));
        return new WalletBalanceView(wallet.getBalance(), wallet.getCurrency(), wallet.getPayeeVpa());
    }

    @Transactional
    public WalletBalanceView addFunds(UUID userId, BigDecimal amount) {
        requirePositiveAmount(amount);
        Wallet wallet = walletRepository.findByUserIdForUpdate(userId)
                .orElseThrow(() -> new WalletNotFoundException("Wallet not found for user"));
        UUID ref = UUID.randomUUID();
        ledgerService.writeSingleWalletCredit(wallet, amount, ref, "Wallet add funds");
        // #region agent log
        DebugNdjson619.append(
                "W1",
                "WalletFundsService.addFunds",
                "post_credit",
                "{\"userId\":\"" + userId + "\",\"balanceAfter\":\"" + wallet.getBalance() + "\"}");
        // #endregion
        log.info("Wallet credited: userId={}, amount={}, balanceAfter={}", userId, amount, wallet.getBalance());
        return new WalletBalanceView(wallet.getBalance(), wallet.getCurrency(), wallet.getPayeeVpa());
    }

    @Transactional
    public WalletBalanceView withdraw(UUID userId, BigDecimal amount) throws InsufficientFundsException {
        requirePositiveAmount(amount);
        Wallet wallet = walletRepository.findByUserIdForUpdate(userId)
                .orElseThrow(() -> new WalletNotFoundException("Wallet not found for user"));
        UUID ref = UUID.randomUUID();
        ledgerService.writeSingleWalletDebit(wallet, amount, ref, "Wallet withdraw");
        // #region agent log
        DebugNdjson619.append(
                "W1",
                "WalletFundsService.withdraw",
                "post_debit",
                "{\"userId\":\"" + userId + "\",\"balanceAfter\":\"" + wallet.getBalance() + "\"}");
        // #endregion
        log.info("Wallet debited: userId={}, amount={}, balanceAfter={}", userId, amount, wallet.getBalance());
        return new WalletBalanceView(wallet.getBalance(), wallet.getCurrency(), wallet.getPayeeVpa());
    }

    private static void requirePositiveAmount(BigDecimal amount) {
        if (amount == null || amount.compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("Amount must be greater than zero");
        }
    }

    public record WalletBalanceView(BigDecimal balance, String currency, String payeeVpa) {}
}
