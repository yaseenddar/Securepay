package com.securepay.transaction.service;

import com.securepay.debug.DebugNdjson619;
import com.securepay.transaction.dto.*;
import com.securepay.transaction.exception.*;
import com.securepay.transaction.model.OutboxEvent;
import com.securepay.transaction.model.Payment;
import com.securepay.transaction.model.Wallet;
//import com.securepay.transaction.model.*;
import com.securepay.transaction.repository.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

// ─────────────────────────────────────────────────────────────────────────────
// PAYMENT SERVICE
// Core orchestration: initiate, process, transition, reverse.
// Most complex class in the service — owns the state machine.
// ─────────────────────────────────────────────────────────────────────────────

@Service
@Slf4j
class PaymentService implements PaymentOperations {

    private final PaymentRepository paymentRepo;
    private final WalletRepository walletRepo;
    private final LedgerService ledgerService;
    private final IdempotencyService idempotencyService;
    private final OutboxService outboxService;

    @Value("${payment.high-value-threshold}")
    private BigDecimal highValueThreshold;

    PaymentService(
            PaymentRepository paymentRepo,
            WalletRepository walletRepo,
            LedgerService ledgerService,
            IdempotencyService idempotencyService,
            OutboxService outboxService
    ) {
        this.paymentRepo        = paymentRepo;
        this.walletRepo         = walletRepo;
        this.ledgerService      = ledgerService;
        this.idempotencyService = idempotencyService;
        this.outboxService      = outboxService;
    }

    // ── INITIATE ──────────────────────────────────────────────────────────────

    /**
     * Initiate a new payment.
     *
     * TRANSACTION: READ_COMMITTED — sufficient here.
     * No balance read/write. Idempotency key UNIQUE constraint
     * handles concurrent first-writes at the DB level.
     *
     * THE HIGH-VALUE GATE:
     * Payments ≥ ₹50,000 with stepUpDone=false → stepUpRequired=true.
     * Payment is saved in RISK_EVALUATED state.
     * Client must:
     *   1. Show user the step-up TOTP prompt
     *   2. Call auth-service /step-up to get new token with stepUpDone=true
     *   3. Retry this endpoint with SAME idempotency key + new token
     *   4. This time stepUpDone=true → payment proceeds to processing
     *
     * WHY same idempotency key on retry?
     * The payment was already created in RISK_EVALUATED state.
     * findExisting() returns it. We check stepUpDone from new token.
     * If stepUpDone=true → call processPayment() on the existing payment.
     * No duplicate payment created.
     *
     * RISK BLOCKING:
     * If riskLevel=HIGH (fraud engine blocks): payment transitions to BLOCKED.
     * BLOCKED is terminal — no retry possible with same key.
     * Client must create a new payment (new idempotency key) if they want to retry.
     * This is intentional — a blocked payment should not be retried silently.
     * @throws InsufficientFundsException 
     */
    @Transactional
    public PaymentResponse initiatePayment(PaymentRequest request, AuthContext auth) throws InsufficientFundsException {
    	 log.info("Processing the Payment for the vpa {}",request.getPayeeVpa());
        // ── Step 1: Idempotency fast-path check ──────────────────────────────
        // Check BEFORE building the entity — avoid wasted work on duplicates.
        Optional<Payment> existing = idempotencyService.findExisting(request.getIdempotencyKey());

        if (existing.isPresent()) {
            Payment found = existing.get();
            log.debug("Duplicate payment request: idempotencyKey={}, existingId={}",
                    request.getIdempotencyKey(), found.getId());

            // If existing payment is in RISK_EVALUATED + stepUpRequired
            // AND the new request has stepUpDone=true → now we can process it
            if (found.isStepUpRequired() && auth.isStepUpDone()
                    && found.getStatus() == PaymentStatus.RISK_EVALUATED) {
                return processPayment(found.getId());
            }

            // All other cases: return existing state
            return toResponse(found);
        }

        String payeeVpa = request.getPayeeVpa() == null ? "" : request.getPayeeVpa().trim();
        assertPayerVpaDoesNotMatchPayee(auth.getUserId(), payeeVpa);

        // ── Step 2: Build new payment entity ──────────────────────────────────
        Payment payment = Payment.builder()
                .idempotencyKey(request.getIdempotencyKey())
                .payerUserId(auth.getUserId())
                .payeeVpa(payeeVpa)
                .amount(request.getAmount())
                .currency("INR")
                .status(PaymentStatus.INITIATED)
                .riskLevel(auth.getRiskLevel())
                .deviceHash(auth.getDeviceHash())
                .stepUpRequired(false)
                .build();

        // ── Step 3: Save with idempotency key — race condition guard ──────────
        try {
            payment = paymentRepo.save(payment);
        } catch (DataIntegrityViolationException ex) {
            // Concurrent request with same idempotency key inserted first.
            // Re-fetch and return their result — fully idempotent.
            Payment concurrent = idempotencyService.handleRaceCondition(
                    request.getIdempotencyKey(), ex);
            log.debug("Race condition on idempotency key={}, returning concurrent result",
                    request.getIdempotencyKey());
            return toResponse(concurrent);
        }

        // ── Step 4: Transition to RISK_EVALUATED ──────────────────────────────
        // Risk level comes from the JWT claim (evaluated at login by auth-service).
        // At payment time we enforce the consequence of that risk score:
        // HIGH risk → investigate further or block
        // LOW/MEDIUM risk → proceed
        log.info("Status check {}",payment.getStatus());
        payment.transitionTo(PaymentStatus.RISK_EVALUATED);
        log.info("Status check {}",payment.getStatus());
        // ── Step 5: High-value gate — step-up auth check ──────────────────────
        boolean isHighValue = payment.isHighValue(highValueThreshold);
        boolean needsStepUp = isHighValue && !auth.isStepUpDone();

        if (needsStepUp) {
            // Mark payment as requiring step-up — stays in RISK_EVALUATED state
            payment.setStepUpRequired(true);
            paymentRepo.save(payment);

            log.info("Step-up required: paymentId={}, amount={}, riskLevel={}",
                    payment.getId(), payment.getAmount(), auth.getRiskLevel());

            // Write PAYMENT_STEP_UP_REQUIRED event for audit trail
            outboxService.writePaymentEvent(payment, "PAYMENT_STEP_UP_REQUIRED");

            return toResponse(payment); // client handles stepUpRequired=true
        }

        // ── Step 6: Risk level blocking ────────────────────────────────────────
        // For Phase 2: HIGH risk on non-high-value payments is flagged but not blocked.
        // A real fraud engine (Phase 3) makes this decision.
        // Here: only block if riskLevel=HIGH AND high-value AND step-up not done.
        // That case is already handled above. Proceed to processing.

        paymentRepo.save(payment);

        // ── Step 7: Process payment (deduct, credit, ledger, outbox) ──────────
        // Call processPayment() within this transaction.
        // IMPORTANT: processPayment() is @Transactional(REQUIRED).
        // Since we're inside initiatePayment()'s transaction, processPayment()
        // JOINS this transaction — same connection, same commit.
        // This is intentional: initiation and processing are one atomic unit.
        return processPayment(payment.getId());
    }

    // ── PROCESS ───────────────────────────────────────────────────────────────

    /**
     * Process payment — the critical method.
     *
     * Can be called:
     * a) From initiatePayment() — initial processing
     * b) From initiatePayment() on step-up retry — deferred processing
     * c) Directly (Phase 6: async processing for high-value payments)
     *
     * LOCKING STRATEGY:
     * Payer wallet   → SELECT FOR UPDATE (pessimistic — high contention)
     * Payment status → @Version (optimistic — low contention)
     *
     * WHY @Transactional on processPayment() AND initiatePayment()?
     * When called FROM initiatePayment():
     *   → Spring's REQUIRED propagation → joins initiatePayment()'s transaction
     *   → one atomic commit covers both initiation and processing
     *
     * When called DIRECTLY (step-up retry, or future async call):
     *   → no outer transaction → starts its own transaction
     *   → stands alone as an atomic unit
     *
     * This dual behavior (join or start) is exactly what REQUIRED propagation provides.
     * No special configuration needed.
     * @throws InsufficientFundsException 
     */
    @Transactional
    public PaymentResponse processPayment(UUID paymentId) throws InsufficientFundsException {
        // ── Step 1: Load payment ──────────────────────────────────────────────
        Payment payment = paymentRepo.findById(paymentId)
                .orElseThrow(() -> new PaymentNotFoundException(paymentId));

        // ── Step 2: Idempotency check — already done? ─────────────────────────
        // Concurrent retry: two threads both call processPayment() for same payment.
        // Thread 1 already succeeded → payment is SUCCESS.
        // Thread 2 arrives here → return existing success result immediately.
        // No double processing.
        if (payment.getStatus() == PaymentStatus.SUCCESS) {
            log.debug("Payment already processed successfully: paymentId={}", paymentId);
            return toResponse(payment);
        }

        if (payment.getStatus().isTerminal()) {
            // BLOCKED, FAILED, REVERSED — cannot process
            throw new IllegalStateTransitionException(
                    "Cannot process payment in terminal state: " + payment.getStatus());
        }

        // ── Step 3: Load payee wallet (regular read — no lock) ────────────────
        // We lock the payer wallet (deduction). Payee wallet credit is safe without
        // a lock — we're only adding money, not checking a threshold.
        // However: reversal needs BOTH locked (for deduction on payee side).
        // For normal payment: only payer needs the exclusive lock.
        Wallet payeeWallet = walletRepo.findByPayeeVpa(payment.getPayeeVpa())
                .orElseThrow(() -> new WalletNotFoundException("Payee not registered"));
        assertPayeeIsNotPayer(payment.getPayerUserId(), payeeWallet);
        if (payment.getPayeeUserId() == null) {
            payment.setPayeeUserId(payeeWallet.getUserId());
        }

        // ── Step 4: Lock payer wallet — SELECT FOR UPDATE ─────────────────────
        //
        // THIS IS THE MOST IMPORTANT LINE IN THE METHOD.
        //
        // After this call:
        // - We have an exclusive lock on the payer's wallet row
        // - Any other transaction calling findByUserIdForUpdate() on this wallet BLOCKS
        // - We read the CURRENT balance — not a snapshot from before other transactions
        // - The lock is held until our @Transactional commits or rolls back
        //
        // WHY acquire payee wallet BEFORE payer lock?
        // payeeWallet is a regular SELECT (no lock). If we locked payer first,
        // then did a regular SELECT for payee, there's no deadlock risk here
        // because the payee SELECT doesn't acquire any lock.
        // BUT: for consistency with reversal (which locks both), we load payee first,
        // then acquire payer lock. Reduces the lock-hold duration.
        Wallet payerWallet = walletRepo.findByUserIdForUpdate(payment.getPayerUserId())
                .orElseThrow(() -> new WalletNotFoundException("Payer not registered"));
        // Do not deduct/credit here — LedgerService.writeDoubleEntry() applies the transfer
        // once and inserts payer DEBIT + payee CREDIT into txn.ledger_entries in the same tx.

        // ── Step 5: Balance check with LOCKED balance ─────────────────────────
        // payerWallet.balance here reflects committed state from ALL prior transactions.
        // This is the point where the SELECT FOR UPDATE pays off:
        // we're reading the actual current balance, not a stale snapshot.
        if (!payerWallet.hasSufficientBalance(payment.getAmount())) {
            payment.markFailed("Insufficient funds: balance="
                    + payerWallet.getBalance() + ", required=" + payment.getAmount());
            paymentRepo.save(payment);
            outboxService.writePaymentEvent(payment, "PAYMENT_FAILED");
            throw new InsufficientFundsException(
                    "Insufficient balance for payment: " + paymentId);
        }

        // ── Step 6: Transition to PROCESSING — @Version guard ─────────────────
        // This UPDATE will fail if another transaction already incremented the version.
        // Generated SQL: UPDATE payments SET status='PROCESSING', version=N+1
        //                WHERE id=? AND version=N
        // If 0 rows affected → OptimisticLockException
        try {
            payment.transitionTo(PaymentStatus.PROCESSING);
            log.info("Status check PROCESSING {}",payment.getStatus());
            paymentRepo.save(payment);

        } catch (ObjectOptimisticLockingFailureException ex) {
            // Another concurrent thread already transitioned this payment.
            // Re-fetch to see what state it's in now.
            log.debug("Optimistic lock conflict on payment={}, re-fetching state", paymentId);

            Payment current = paymentRepo.findById(paymentId)
                    .orElseThrow(() -> new PaymentNotFoundException(paymentId));

            if (current.getStatus() == PaymentStatus.SUCCESS) {
                // The other thread already completed successfully — return its result
                return toResponse(current);
            }

            // In any other state: something went wrong in the other thread
            // Propagate the locking failure — caller handles retry
            throw ex;
        }

        // ── Step 7: Double-entry ledger write ─────────────────────────────────
        // This is called WITHOUT @Transactional — participates in our transaction.
        // deduct + credit + save wallets + write 2 ledger entries — all atomic.
        // If this throws (InsufficientFundsException — shouldn't happen, we checked):
        // → entire transaction rolls back
        // → payment stays in PROCESSING (will be reconciled by cleanup job)
        try {
            ledgerService.writeDoubleEntry(
                    payerWallet,
                    payeeWallet,
                    payment.getAmount(),
                    payment.getId(),
                    "Payment: " + payment.getPayeeVpa()
            );
            // #region agent log
            DebugNdjson619.append(
                    "P2",
                    "PaymentService.processPayment",
                    "ledger_write_ok",
                    "{\"paymentId\":\"" + payment.getId() + "\",\"payerWalletId\":\""
                            + payerWallet.getId() + "\",\"payeeWalletId\":\"" + payeeWallet.getId() + "\"}");
            // #endregion
        } catch (InsufficientFundsException ex) {
            // #region agent log
            DebugNdjson619.append(
                    "P2",
                    "PaymentService.processPayment",
                    "ledger_write_failed",
                    "{\"paymentId\":\"" + payment.getId() + "\"}");
            // #endregion
            // This should not happen — we checked balance above with the locked wallet.
            // If it does: data inconsistency between our check and the domain method.
            // Fail the payment explicitly and propagate.
            payment.markFailed("Balance check passed but deduction failed: " + ex.getMessage());
            paymentRepo.save(payment);
            outboxService.writePaymentEvent(payment, "PAYMENT_FAILED");
            throw ex;
        }

        // ── Step 8: Transition to SUCCESS ─────────────────────────────────────
        payment.transitionTo(PaymentStatus.SUCCESS);
        paymentRepo.save(payment);

        // ── Step 9: Write outbox event — Outbox Pattern ───────────────────────
        // SAME TRANSACTION as steps 3–8.
        // If this fails: entire transaction rolls back.
        // Payment goes back to PROCESSING state in DB (rolled back).
        // Next reconciliation job detects PROCESSING payments > threshold age
        // and re-processes or marks failed. (Phase 6 concern)
        //
        // If commit succeeds: payment is SUCCESS AND outbox event is durable.
        // OutboxPublisher will send to Kafka. At-least-once delivery guaranteed.
        outboxService.writePaymentEvent(payment, "PAYMENT_SUCCESS");

        log.info("Payment processed successfully: paymentId={}, amount={}, payer={}, payeeVpa={}",
                payment.getId(), payment.getAmount(),
                payment.getPayerUserId(), payment.getPayeeVpa());

        return toResponse(payment);
    }

    // ── REVERSE ───────────────────────────────────────────────────────────────

    /**
     * Reverse a successful payment.
     *
     * ATOMIC OPERATION:
     * State transition + ledger reversal + outbox event = one transaction.
     * Either all succeed or none persist.
     *
     * PAYEE INSOLVENCY:
     * The payee may have spent the received money. They might have ₹0 when
     * we try to deduct ₹500 from them for reversal.
     * This throws InsufficientFundsException from LedgerService.writeReverseEntry().
     * Transaction rolls back. Reversal fails.
     * In production: overdraft allowance or manual dispute resolution for this case.
     * Phase 2: let it fail with InsufficientFundsException — caller handles.
     *
     * LOCK ORDER:
     * Always lockWalletsInOrder() — see LedgerService for deadlock explanation.
     * @throws InsufficientFundsException 
     */
    @Transactional
    public PaymentResponse reversePayment(UUID paymentId, String reason, AuthContext auth)
            throws InsufficientFundsException {

        // ── Load and validate ─────────────────────────────────────────────────
        Payment payment = paymentRepo.findById(paymentId)
                .orElseThrow(() -> new PaymentNotFoundException(paymentId));
        if (!payment.getPayerUserId().equals(auth.getUserId())) {
            throw new PaymentNotFoundException(paymentId);
        }

        // Only SUCCESS payments can be reversed — state machine enforces this
        if (payment.getStatus() != PaymentStatus.SUCCESS) {
            throw new IllegalStateTransitionException(
                    "Only SUCCESS payments can be reversed. Current status: "
                            + payment.getStatus());
        }

        // ── Lock both wallets in deterministic order ───────────────────────────
        // lockWalletsInOrder acquires SELECT FOR UPDATE on both wallets.
        // Returns [payerWallet, payeeWallet] regardless of lock acquisition order.
        Wallet[] wallets = ledgerService.lockWalletsInOrder(
                payment.getPayerUserId(),
                payment.getPayeeUserId()
        );
        Wallet payerWallet = wallets[0];
        Wallet payeeWallet = wallets[1];

        // ── Transition to REVERSED ────────────────────────────────────────────
        // @Version check: ensures no concurrent modification snuck in
        payment.transitionTo(PaymentStatus.REVERSED);
        payment.setFailureReason(reason);
        paymentRepo.save(payment);

        // ── Write reverse ledger entries ──────────────────────────────────────
        // CREDIT payer (money returns), DEBIT payee (money taken back)
        ledgerService.writeReverseEntry(
                payerWallet,
                payeeWallet,
                payment.getAmount(),
                payment.getId(),
                "Reversal: " + (reason != null ? reason : "Payment reversed")
        );

        // ── Write outbox event ────────────────────────────────────────────────
        outboxService.writePaymentEvent(payment, "PAYMENT_REVERSED");

        log.info("Payment reversed: paymentId={}, amount={}, reason={}",
                paymentId, payment.getAmount(), reason);

        return toResponse(payment);
    }

    // ── GET ───────────────────────────────────────────────────────────────────

    /**
     * Read-only payment status lookup.
     *
     * @Transactional(readOnly = true):
     * - Tells Hibernate: don't flush dirty entities (we won't modify anything)
     * - Tells connection pool: this connection can be routed to a read replica
     * - Disables Hibernate's dirty-checking mechanism → slight performance gain
     *
     * Even though it's "just a SELECT," the @Transactional ensures we see
     * a consistent snapshot — no partial writes from concurrent transactions.
     */
    @Transactional(readOnly = true)
    public PaymentResponse getPayment(UUID paymentId, AuthContext auth) {
        Payment payment = paymentRepo.findById(paymentId)
                .orElseThrow(() -> new PaymentNotFoundException(paymentId));
        if (!payment.getPayerUserId().equals(auth.getUserId())) {
            throw new PaymentNotFoundException(paymentId);
        }
        return toResponse(payment);
    }

    /** Payer and payee must be different users (no paying your own VPA / wallet). */
    private static void assertPayeeIsNotPayer(UUID payerUserId, Wallet payeeWallet) {
        if (payeeWallet.getUserId().equals(payerUserId)) {
            throw new IllegalArgumentException("Cannot send payment to your own VPA");
        }
    }

    /**
     * Reject when payee VPA string matches the payer's registered wallet VPA (same user).
     */
    private void assertPayerVpaDoesNotMatchPayee(UUID payerUserId, String payeeVpa) {
        if (payeeVpa == null || payeeVpa.isBlank()) {
            return;
        }
        walletRepo.findByUserId(payerUserId).ifPresent(payerWallet -> {
            String payerVpa = payerWallet.getPayeeVpa();
            if (payerVpa != null && !payerVpa.isBlank()
                    && payerVpa.trim().equalsIgnoreCase(payeeVpa.trim())) {
                throw new IllegalArgumentException("Cannot send payment to your own VPA");
            }
        });
    }

    // ── MAPPER ────────────────────────────────────────────────────────────────

    /**
     * Map Payment entity to PaymentResponse DTO.
     *
     * WHY not use MapStruct or ModelMapper?
     * For Phase 2: explicit mapping makes the transformation visible.
     * You see exactly what fields are exposed — no accidental field exposure.
     * Phase 6: add MapStruct for reducing boilerplate at scale.
     */
    private PaymentResponse toResponse(Payment payment) {
        return PaymentResponse.builder()
                .paymentId(payment.getId())
                .idempotencyKey(payment.getIdempotencyKey())
                .status(payment.getStatus())
                .amount(payment.getAmount())
                .payeeVpa(payment.getPayeeVpa())
                .stepUpRequired(payment.isStepUpRequired())
                .failureReason(payment.getFailureReason())
                .initiatedAt(payment.getInitiatedAt())
                .completedAt(payment.getCompletedAt())
                .build();
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// IDEMPOTENCY SERVICE
// Deduplication guard — same key = same result.
// ─────────────────────────────────────────────────────────────────────────────

@Service
@Slf4j
class IdempotencyService {

    private final PaymentRepository paymentRepo;

    IdempotencyService(PaymentRepository paymentRepo) {
        this.paymentRepo = paymentRepo;
    }

    /**
     * Fast-path duplicate check.
     *
     * Called BEFORE any payment entity is built or saved.
     * If key exists: return existing payment immediately.
     * No entity construction, no BCrypt-equivalent work wasted.
     *
     * WHY Optional and not throw DuplicatePaymentException here?
     * The caller (PaymentService) decides how to handle the duplicate.
     * For some callers it's a success (return existing response).
     * For others it might be an error (POST to idempotent endpoint that
     * expects first-time only). Returning Optional keeps the decision
     * at the right level — the orchestrator.
     */
    public Optional<Payment> findExisting(String idempotencyKey) {
        return paymentRepo.findByIdempotencyKey(idempotencyKey);
    }

    /**
     * Race condition recovery after UNIQUE constraint violation.
     *
     * THE SCENARIO:
     * T1: findExisting() → empty (not found)
     * T2: findExisting() → empty (not found)
     * T1: INSERT payment → success, commits
     * T2: INSERT payment → DataIntegrityViolationException (UNIQUE on idempotency_key)
     *
     * T2 catches DIVE and calls this method.
     * T1's row now exists → findByIdempotencyKey returns it.
     * T2 returns T1's payment as if it had found it in the first check.
     * Client receives consistent response regardless of which thread "won."
     *
     * THE THIRD FIND:
     * If this re-fetch ALSO returns empty, something is deeply wrong:
     * - Constraint fired (row must exist) but SELECT finds nothing
     * - Possible causes: replication lag on read replica, transaction isolation issue
     * - Not recoverable at application level → propagate the original exception
     *
     * This is the same pattern as DeviceFingerprintService.findOrRegisterDevice().
     * Same problem (concurrent first-write), same solution (catch, re-fetch).
     */
    public Payment handleRaceCondition(
            String idempotencyKey,
            DataIntegrityViolationException ex
    ) {
        log.debug("Idempotency key race condition detected for key={}, re-fetching", idempotencyKey);

        return paymentRepo.findByIdempotencyKey(idempotencyKey)
                .orElseThrow(() -> new IllegalStateException(
                        "UNIQUE constraint fired for key=" + idempotencyKey +
                        " but row not found on re-fetch — possible DB inconsistency",
                        ex
                ));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OUTBOX SERVICE
// Writes events to outbox table in same transaction as domain changes.
// ─────────────────────────────────────────────────────────────────────────────

@Service
@Slf4j
class OutboxService {

    private final OutboxEventRepository outboxRepo;
    private final com.fasterxml.jackson.databind.ObjectMapper objectMapper;

    @Value("${kafka.topics.payment-events}")
    private String paymentEventsTopic;

    OutboxService(
            OutboxEventRepository outboxRepo,
            com.fasterxml.jackson.databind.ObjectMapper objectMapper
    ) {
        this.outboxRepo   = outboxRepo;
        this.objectMapper = objectMapper;
    }

    /**
     * Write payment event to outbox — in the SAME transaction as domain change.
     *
     * THIS IS THE HEART OF THE OUTBOX PATTERN.
     *
     * Why this works:
     * PaymentService.processPayment() is @Transactional.
     * That transaction:
     *   1. Updates payment status → SUCCESS
     *   2. Updates wallet balances
     *   3. Writes ledger entries
     *   4. Calls this method → writes outbox event
     * All four steps commit or rollback together.
     *
     * BEFORE Outbox Pattern:
     *   payment committed to DB
     *   kafkaTemplate.send() called
     *   app crashes before Kafka receives it → event lost forever
     *
     * WITH Outbox Pattern:
     *   payment committed to DB AND outbox event committed to DB (atomically)
     *   app crashes → outbox row survives → OutboxPublisher resends on restart
     *   No event lost. At-least-once delivery guaranteed.
     *
     * PAYLOAD SNAPSHOT:
     * We serialize the payment state NOW (at event creation time).
     * OutboxPublisher runs later — by then payment state may have changed further.
     * The event must capture the state AT THE MOMENT IT OCCURRED.
     * "PAYMENT_SUCCESS" event should contain the payment data at the moment of success,
     * not whatever state the payment is in when the publisher finally sends it.
     *
     * PARTITION KEY = paymentId:
     * Stored as aggregateId. OutboxPublisher uses this as Kafka partition key.
     * All events for the same payment → same Kafka partition → ordered delivery.
     * Fraud Engine receives PAYMENT_INITIATED before PAYMENT_SUCCESS. Always.
     */
    public void writePaymentEvent(Payment payment, String eventType) {
        // ── Serialize payment state as JSON snapshot ──────────────────────────
        String payload;
        try {
            // Build a snapshot map — don't serialize the full JPA entity
            // (lazy-loaded collections, Hibernate proxies cause issues with ObjectMapper)
            var snapshot = java.util.Map.of(
                    "paymentId",     payment.getId().toString(),
                    "idempotencyKey", payment.getIdempotencyKey(),
                    "payerUserId",   payment.getPayerUserId().toString(),
                    "payeeVpa",      payment.getPayeeVpa(),
                    "amount",        payment.getAmount().toPlainString(),
                    "currency",      payment.getCurrency(),
                    "status",        payment.getStatus().name(),
                    "eventType",     eventType,
                    "occurredAt",    java.time.LocalDateTime.now().toString()
            );
            payload = objectMapper.writeValueAsString(snapshot);
        } catch (com.fasterxml.jackson.core.JsonProcessingException ex) {
            // JSON serialization failure — this should never happen with a simple Map
            // If it does: log + throw, let the transaction rollback
            // Better to rollback the payment than to commit without an outbox event
            throw new IllegalStateException(
                    "Failed to serialize payment event payload for paymentId=" + payment.getId(), ex);
        }

        // ── Build and persist outbox event ────────────────────────────────────
        OutboxEvent event = OutboxEvent.builder()
                .aggregateType("PAYMENT")
                .aggregateId(payment.getId())       // Kafka partition key
                .eventType(eventType)               // "PAYMENT_SUCCESS", "PAYMENT_FAILED" etc.
                .topic(paymentEventsTopic)
                .payload(payload)
                .published(false)                   // publisher will set this to true
                .retryCount(0)
                .build();

        outboxRepo.save(event);

        log.debug("Outbox event written: eventType={}, paymentId={}, topic={}",
                eventType, payment.getId(), paymentEventsTopic);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// OUTBOX PUBLISHER
// Polls outbox table and publishes to Kafka.
// Runs on a schedule — separate from the domain transaction.
// ─────────────────────────────────────────────────────────────────────────────

//@Service
//@Slf4j
//class OutboxPublisher {
//
//    private final OutboxEventRepository outboxRepo;
//    private final KafkaTemplate<String, String> kafkaTemplate;
//
//    @Value("${outbox.publisher.batch-size}")
//    private int batchSize;
//
//    OutboxPublisher(
//            OutboxEventRepository outboxRepo,
//            KafkaTemplate<String, String> kafkaTemplate
//    ) {
//        this.outboxRepo    = outboxRepo;
//        this.kafkaTemplate = kafkaTemplate;
//    }
//
//    /**
//     * Poll outbox and publish pending events to Kafka.
//     *
//     * ── SCHEDULING ───────────────────────────────────────────────────────────
//     * @Scheduled(fixedDelay) means: wait N ms AFTER the previous execution
//     * finishes before starting the next one. Not a fixed rate.
//     *
//     * WHY fixedDelay and not fixedRate?
//     * fixedRate fires every N ms regardless of how long the job takes.
//     * If the job takes 2s and fixedRate=1s, executions pile up.
//     * fixedDelay waits N ms after completion — next run starts only after
//     * previous finishes. No pile-up. Predictable load on DB and Kafka.
//     *
//     * ── SHEDLOCK ─────────────────────────────────────────────────────────────
//     * @SchedulerLock acquires an exclusive lock in the shedlock DB table.
//     * Only ONE pod runs this job at any instant across the entire cluster.
//     *
//     * lockAtMostFor = "PT30S" (ISO 8601 duration = 30 seconds):
//     * Maximum time any pod can hold the lock.
//     * If the pod holding the lock crashes mid-job, this is the safety valve.
//     * After 30s, the lock is considered stale → another pod can take over.
//     * Set this to: (expected max job duration) × 3 for safety margin.
//     *
//     * lockAtLeastFor = "PT5S":
//     * Minimum hold time. Prevents a fast pod from hogging the lock by
//     * finishing in 10ms and immediately re-acquiring. Other pods never get
//     * a chance. 5s minimum gives fair distribution across pods.
//     *
//     * ── TRANSACTION BOUNDARY ─────────────────────────────────────────────────
//     * This method is NOT @Transactional for a deliberate reason.
//     *
//     * The publish loop needs to:
//     * 1. Send to Kafka (external system — outside any DB transaction)
//     * 2. Mark as published in DB
//     *
//     * If we wrapped everything in @Transactional:
//     * - Kafka sends would happen inside an open DB transaction
//     * - Long-running transactions holding DB connections = connection pool exhaustion
//     * - Kafka send success/failure can't be rolled back anyway
//     *
//     * Instead: each event is its own mini-operation.
//     * markPublished() runs in its own short @Modifying query.
//     * No long-held DB connections.
//     *
//     * ── KAFKA SEND IS ASYNC ──────────────────────────────────────────────────
//     * kafkaTemplate.send() returns a CompletableFuture<SendResult>.
//     * The send is asynchronous — it returns immediately, Kafka brokers
//     * acknowledge in the background.
//     *
//     * We call .get(5, TimeUnit.SECONDS) to wait for the ack synchronously.
//     * WHY wait? If we don't wait and the send fails silently:
//     * - We'd mark the event as published (it wasn't)
//     * - Event is lost forever (no retry)
//     *
//     * Waiting for ack means: Kafka brokers confirmed receipt.
//     * Only then do we mark published=true.
//     *
//     * The 5-second timeout is the max wait per event.
//     * With batch size 50: worst case = 50 × 5s = 250s per cycle.
//     * In practice: acks arrive in ~5ms on a healthy cluster.
//     */
//    @Scheduled(fixedDelayString = "${outbox.publisher.poll-interval-ms}")
//    @net.javacrumbs.shedlock.spring.annotation.SchedulerLock(
//            name = "outbox_publisher",
//            lockAtMostFor  = "${outbox.publisher.lock-at-most-seconds}000ms",
//            lockAtLeastFor = "${outbox.publisher.lock-at-least-seconds}000ms"
//    )
//    public void publishPendingEvents() {
//        // ── Load a bounded batch of unpublished events ────────────────────────
//        // PageRequest.of(0, batchSize): first page, batchSize rows.
//        // Ordered by createdAt ASC — FIFO, oldest events published first.
//        // Partial index idx_outbox_unpublished covers this query efficiently.
//        List<OutboxEvent> pending = outboxRepo.findUnpublishedEvents(
//                org.springframework.data.domain.PageRequest.of(0, batchSize)
//        );
//
//        if (pending.isEmpty()) {
//            return; // nothing to publish — common case, exit fast
//        }
//
//        int published = 0;
//        int failed    = 0;
//
//        for (OutboxEvent event : pending) {
//            try {
//                // ── Send to Kafka — synchronous ack wait ──────────────────────
//                // Partition key = aggregateId (paymentId as string).
//                // All events for same payment → same partition → ordered delivery.
//                kafkaTemplate.send(
//                        event.getTopic(),
//                        event.getAggregateId().toString(), // partition key
//                        event.getPayload()
//                ).get(5, java.util.concurrent.TimeUnit.SECONDS);
//                // .get() blocks until Kafka brokers ack the message
//                // Throws ExecutionException if Kafka rejects
//                // Throws TimeoutException if no ack in 5 seconds
//
//                // ── Mark published — short targeted UPDATE ───────────────────
//                // @Modifying query: UPDATE outbox_events SET published=true WHERE id=?
//                // Single statement, no entity load, committed immediately.
//                // NOT in a transaction — this is a one-way write, no rollback needed.
//                outboxRepo.markPublished(event.getId(), LocalDateTime.now());
//                published++;
//
//                log.debug("Event published: id={}, type={}, paymentId={}",
//                        event.getId(), event.getEventType(), event.getAggregateId());
//
//            } catch (java.util.concurrent.TimeoutException ex) {
//                // ── Kafka timed out — broker may be slow or unreachable ───────
//                handlePublishFailure(event,
//                        "Kafka send timed out after 5s: " + ex.getMessage());
//                failed++;
//
//            } catch (java.util.concurrent.ExecutionException ex) {
//                // ── Kafka rejected the message ─────────────────────────────────
//                // Possible causes: serialization error, topic doesn't exist,
//                // authorization failure, broker returned an error.
//                handlePublishFailure(event,
//                        "Kafka send failed: " + ex.getCause().getMessage());
//                failed++;
//
//            } catch (InterruptedException ex) {
//                // ── Thread interrupted — probably application shutdown ──────────
//                // Restore interrupt flag and stop processing.
//                // Don't record as failure — the event will be retried on restart.
//                Thread.currentThread().interrupt();
//                log.warn("OutboxPublisher interrupted during send — stopping batch");
//                break;
//
//            } catch (Exception ex) {
//                // ── Unexpected exception ──────────────────────────────────────
//                handlePublishFailure(event, "Unexpected error: " + ex.getMessage());
//                failed++;
//                log.error("Unexpected error publishing event={}", event.getId(), ex);
//            }
//        }
//
//        // ── Batch statistics ──────────────────────────────────────────────────
//        if (published > 0 || failed > 0) {
//            log.info("Outbox batch complete: published={}, failed={}, batchSize={}",
//                    published, failed, pending.size());
//        }
//
//        // ── Alert on dead letters ─────────────────────────────────────────────
//        // Check if any events have crossed the dead-letter threshold (5 retries).
//        // In production: integrate with PagerDuty / Alertmanager here.
//        List<OutboxEvent> deadLetters = outboxRepo.findDeadLetterEvents();
//        if (!deadLetters.isEmpty()) {
//            log.error("DEAD LETTER EVENTS DETECTED: count={}. Manual intervention required.",
//                    deadLetters.size());
//            deadLetters.forEach(dl ->
//                    log.error("Dead letter: id={}, type={}, paymentId={}, lastError={}",
//                            dl.getId(), dl.getEventType(),
//                            dl.getAggregateId(), dl.getLastError())
//            );
//        }
//    }
//
//    /**
//     * Record a publish failure on the event.
//     *
//     * event.recordFailure() increments retryCount and stores the error message.
//     * If retryCount reaches 5: event.isDeadLetter() returns true.
//     * Dead letter events are excluded from future polling
//     * (findUnpublishedEvents filters retryCount < 5).
//     *
//     * WHY save with @Transactional here and not in the main loop?
//     * The failure record is a separate concern from the publish attempt.
//     * If we fail to save the failure record (DB down), that's acceptable —
//     * the event will still be retried on next poll cycle (retryCount stays 0).
//     * We don't want a DB failure during failure recording to mask the
//     * original Kafka failure.
//     */
//    @Transactional
//    protected void handlePublishFailure(OutboxEvent event, String error) {
//        event.recordFailure(error);
//        outboxRepo.save(event);
//
//        if (event.isDeadLetter()) {
//            log.error("Event moved to dead letter: id={}, type={}, retries={}, error={}",
//                    event.getId(), event.getEventType(), event.getRetryCount(), error);
//        } else {
//            log.warn("Event publish failed (retry {}/5): id={}, error={}",
//                    event.getRetryCount(), event.getId(), error);
//        }
//    }
//}