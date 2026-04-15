package com.securepay.transaction.service;

import java.math.BigDecimal;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.securepay.transaction.exception.InsufficientFundsException;
import com.securepay.transaction.exception.WalletNotFoundException;
import com.securepay.transaction.model.LedgerEntry;
import com.securepay.transaction.model.Wallet;
import com.securepay.transaction.repository.LedgerEntryRepository;
import com.securepay.transaction.repository.WalletRepository;
import com.securepay.transaction.service.LedgerService;

import lombok.extern.slf4j.Slf4j;

//─────────────────────────────────────────────────────────────────────────────
//LEDGER SERVICE
//Double-entry writes — always debit one side, credit the other.
//─────────────────────────────────────────────────────────────────────────────

@Service
@Slf4j
class LedgerService {

 private final LedgerEntryRepository ledgerRepo;
 private final WalletRepository walletRepo;

 LedgerService(LedgerEntryRepository ledgerRepo, WalletRepository walletRepo) {
     this.ledgerRepo = ledgerRepo;
     this.walletRepo = walletRepo;
 }

 /**
  * Write double-entry for a payment.
  *
  * NOT @Transactional — intentional design.
  * This method participates in the CALLER's transaction (PaymentService.processPayment).
  * The caller already holds SELECT FOR UPDATE locks on both wallets.
  * Adding @Transactional here would be harmless (REQUIRED joins outer tx),
  * but the absence is a deliberate signal: "I am not self-contained.
  * I depend on my caller's transaction and locks."
  *
  * This is the "Tell, Don't Ask" principle applied to transactions:
  * the caller knows what locks it holds and what atomicity it needs.
  * The ledger service just does arithmetic — it doesn't manage that context.
  *
  * OPERATION ORDER MATTERS:
  * 1. Deduct first (throws InsufficientFundsException if balance < amount)
  * 2. Only if deduction succeeds → credit the other side
  * This ensures we never credit a payee when payer has insufficient funds.
  *
  * 3. Save wallets BEFORE writing ledger entries.
  * WHY? balance_after in each ledger entry must reflect the FINAL balance
  * after the arithmetic. If we saved ledger first, balance_after would
  * capture an intermediate state.
  *
  * 4. Ledger entries written AFTER wallet saves.
  * WHY? If ledger insert fails, wallet saves also rollback (same transaction).
  * No partial writes. Both wallets and both ledger entries are atomic.
 * @throws InsufficientFundsException 
  */
 public void writeDoubleEntry(
         Wallet payerWallet,
         Wallet payeeWallet,
         BigDecimal amount,
         UUID paymentId,
         String description
 ) throws InsufficientFundsException {
     // ── Step 1: Arithmetic — deduct from payer, credit to payee ──────────
     // Wallet.deduct() enforces non-negative balance at domain level.
     // DB CHECK CONSTRAINT (balance >= 0) enforces it at DB level.
     // Two layers — application is first, DB is last resort.
     payerWallet.deduct(amount);    // throws InsufficientFundsException if balance < amount
     payeeWallet.credit(amount);

     // ── Step 2: Persist updated wallet balances ───────────────────────────
     // These wallets are already locked (SELECT FOR UPDATE by caller).
     // save() here generates: UPDATE wallets SET balance=?, updated_at=? WHERE id=?
     // No version column on Wallet (we use SELECT FOR UPDATE instead of @Version).
     walletRepo.save(payerWallet);
     walletRepo.save(payeeWallet);

     // ── Step 3: Write immutable ledger entries ────────────────────────────
     // DEBIT entry: money leaving payerWallet
     // balanceAfter = payerWallet.getBalance() AFTER deduction (already done in step 1)
     LedgerEntry debitEntry = LedgerEntry.builder()
             .paymentId(paymentId)
             .walletId(payerWallet.getId())
             .entryType(LedgerEntry.EntryType.DEBIT)
             .amount(amount)
             .balanceAfter(payerWallet.getBalance())  // post-deduction balance
             .description(description != null ? description : "Payment debit")
             .build();

     // CREDIT entry: money arriving at payeeWallet
     LedgerEntry creditEntry = LedgerEntry.builder()
             .paymentId(paymentId)
             .walletId(payeeWallet.getId())
             .entryType(LedgerEntry.EntryType.CREDIT)
             .amount(amount)
             .balanceAfter(payeeWallet.getBalance())  // post-credit balance
             .description(description != null ? description : "Payment credit")
             .build();

     ledgerRepo.save(debitEntry);
     ledgerRepo.save(creditEntry);

     // ── Invariant assertion (dev/test safety net) ─────────────────────────
     // In production: remove this assert or gate it behind a feature flag.
     // In tests: this catches bugs where debit and credit amounts diverge.
     assert debitEntry.getAmount().compareTo(creditEntry.getAmount()) == 0
             : "Double-entry invariant violated: debit != credit for paymentId=" + paymentId;

     log.debug("Double entry written: paymentId={}, amount={}, payerBalance={}, payeeBalance={}",
             paymentId, amount,
             payerWallet.getBalance(),
             payeeWallet.getBalance());
 }

 /**
  * Write REVERSE double-entry (credit payer, debit payee).
  *
  * Mirror of writeDoubleEntry() — used in reversePayment().
  * Money flows back: payee → payer.
  *
  * WHY a separate method instead of swapping arguments?
  * Naming matters for audit clarity.
  * writeDoubleEntry(payee, payer, ...) looks like a bug — are the args swapped?
  * writeReverseEntry(payer, payee, ...) is unambiguous: reversal of the forward direction.
 * @throws InsufficientFundsException 
  */
 public void writeReverseEntry(
         Wallet payerWallet,
         Wallet payeeWallet,
         BigDecimal amount,
         UUID paymentId,
         String description
 ) throws InsufficientFundsException {
     // Reversal: credit payer (money returns), debit payee (money taken back)
     payerWallet.credit(amount);
     payeeWallet.deduct(amount);   // payee might not have enough if they spent it

     walletRepo.save(payerWallet);
     walletRepo.save(payeeWallet);

     // CREDIT for payer — returning money
     LedgerEntry creditEntry = LedgerEntry.builder()
             .paymentId(paymentId)
             .walletId(payerWallet.getId())
             .entryType(LedgerEntry.EntryType.CREDIT)
             .amount(amount)
             .balanceAfter(payerWallet.getBalance())
             .description(description != null ? description : "Payment reversal credit")
             .build();

     // DEBIT for payee — taking money back
     LedgerEntry debitEntry = LedgerEntry.builder()
             .paymentId(paymentId)
             .walletId(payeeWallet.getId())
             .entryType(LedgerEntry.EntryType.DEBIT)
             .amount(amount)
             .balanceAfter(payeeWallet.getBalance())
             .description(description != null ? description : "Payment reversal debit")
             .build();

     ledgerRepo.save(creditEntry);
     ledgerRepo.save(debitEntry);

     log.debug("Reverse entry written: paymentId={}, amount={}", paymentId, amount);
 }

 /**
  * Lock two wallets in deterministic order to prevent deadlock.
  *
  * FOUR CONDITIONS FOR DEADLOCK (all must hold simultaneously):
  * 1. Mutual exclusion — only one thread can hold a lock
  * 2. Hold and wait — thread holds one lock while waiting for another
  * 3. No preemption — locks can't be forcibly taken away
  * 4. Circular wait — T1 waits for T2, T2 waits for T1
  *
  * We break condition 4 (circular wait) by imposing a GLOBAL ORDERING.
  * If every thread always requests locks in the same order,
  * circular wait is impossible — the last lock in the ordering can always
  * be acquired without waiting for anyone who waits for you.
  *
  * UUID lexicographic ordering is our global ordering.
  * String.compareTo() on UUID strings gives consistent ordering
  * across all threads, all pods, all time.
  *
  * RETURNS:
  * Wallet[] where [0] = payerWallet, [1] = payeeWallet
  * Caller needs payer/payee distinction for debit/credit operations.
  * The locking ORDER is internal — the return order matches caller's intent.
  */
 public Wallet[] lockWalletsInOrder(UUID payerUserId, UUID payeeUserId) {
     // ── Determine lock acquisition order ─────────────────────────────────
     // Compare UUID strings lexicographically.
     // compareTo < 0: payerUserId is "smaller" → lock payer first
     // compareTo > 0: payeeUserId is "smaller" → lock payee first
     // compareTo == 0: same user (self-payment) — edge case, lock once
     boolean lockPayerFirst = payerUserId.toString()
             .compareTo(payeeUserId.toString()) <= 0;

     Wallet payerWallet;
     Wallet payeeWallet;

     if (lockPayerFirst) {
         // Payer UUID is lexicographically smaller → lock payer first
         payerWallet = walletRepo.findByUserIdForUpdate(payerUserId)
                 .orElseThrow(() -> new WalletNotFoundException("payerWallet not found"));
         payeeWallet = walletRepo.findByUserIdForUpdate(payeeUserId)
                 .orElseThrow(() -> new WalletNotFoundException("payeeWallet not found"));
     } else {
         // Payee UUID is lexicographically smaller → lock payee first
         // Still return [payer, payee] — caller needs this distinction
         payeeWallet = walletRepo.findByUserIdForUpdate(payeeUserId)
                 .orElseThrow(() -> new WalletNotFoundException("payeeWallet not found"));
         payerWallet = walletRepo.findByUserIdForUpdate(payerUserId)
                 .orElseThrow(() -> new WalletNotFoundException("payerWallet not found"));
     }

     log.debug("Wallets locked in order: first={}, second={}",
             lockPayerFirst ? payerUserId : payeeUserId,
             lockPayerFirst ? payeeUserId : payerUserId);

     return new Wallet[]{payerWallet, payeeWallet};
 }

 /**
  * Compute balance from ledger — source of truth for reconciliation.
  *
  * This is the AUTHORITATIVE balance computation.
  * wallet.balance is a cache. This is what it should equal.
  *
  * If computeBalanceFromLedger(walletId) != wallet.balance:
  * → There is a bug in the write path.
  * → Either a wallet was updated without a ledger entry.
  * → Or a ledger entry was written without updating the wallet.
  * → Both are critical bugs. Alert immediately.
  *
  * Returns BigDecimal.ZERO if no ledger entries exist (fresh wallet).
  */
 @Transactional(readOnly = true)
 public BigDecimal computeBalanceFromLedger(UUID walletId) {
     BigDecimal computed = ledgerRepo.computeBalanceFromLedger(walletId);
     // computeBalanceFromLedger returns null if no entries exist (SUM of empty set)
     return computed != null ? computed : BigDecimal.ZERO;
 }
}
