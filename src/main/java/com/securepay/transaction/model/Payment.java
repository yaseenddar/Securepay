package com.securepay.transaction.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.UpdateTimestamp;

import com.securepay.auth.model.RiskLevel;
import com.securepay.transaction.dto.PaymentStatus;
import com.securepay.transaction.exception.InsufficientFundsException;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

//─────────────────────────────────────────────────────────────────────────────
//PAYMENT ENTITY
//─────────────────────────────────────────────────────────────────────────────

/**
* Core payment entity.
*
* @Version — optimistic locking on status transitions.
* Each transition does: UPDATE ... SET status=?, version=N+1 WHERE id=? AND version=N
* If another transaction already incremented version → 0 rows affected
* → Hibernate throws OptimisticLockException → caller retries or rejects.
*
* Domain logic lives here — not in the service:
* - transitionTo() validates state machine
* - isHighValue() encapsulates threshold knowledge
* - markCompleted() sets completedAt on terminal transition
*
* WHY BigDecimal for amount (not double/float)?
* double and float use IEEE 754 binary floating point.
* 0.1 + 0.2 = 0.30000000000000004 in binary floating point.
* Financial calculations MUST be exact.
* BigDecimal is decimal-precise — no rounding errors.
* Store as NUMERIC(15,2) in PostgreSQL — exact decimal storage.
*/
@Entity
@Table(name = "payments", schema = "txn")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Payment {

  @Id
  @GeneratedValue(strategy = GenerationType.UUID)
  private UUID id;

  @Column(name = "idempotency_key", nullable = false, unique = true, length = 64)
  private String idempotencyKey;

  @Column(name = "payer_user_id", nullable = false)
  private UUID payerUserId;

  @Column(name = "payee_vpa", nullable = false, length = 100)
  private String payeeVpa;

  @Column(name = "payee_user_id")
  private UUID payeeUserId;

  @Column(nullable = false, precision = 15, scale = 2)
  private BigDecimal amount;

  @Column(nullable = false, length = 3)
  private String currency = "INR";

  @Enumerated(EnumType.STRING)
  @Column(nullable = false, length = 20)
  private PaymentStatus status = PaymentStatus.INITIATED;

  @Column(name = "risk_level", length = 10)
  private RiskLevel riskLevel;

  @Column(name = "step_up_required")
  private boolean stepUpRequired = false;

  @Column(name = "failure_reason", length = 255)
  private String failureReason;

  @Column(name = "device_hash", length = 64)
  private String deviceHash;

  @Column(name = "initiated_at", updatable = false)
  private LocalDateTime initiatedAt = LocalDateTime.now();

  @Column(name = "completed_at")
  private LocalDateTime completedAt;

  /**
   * @Version — Hibernate manages this field.
   * On every UPDATE: WHERE version = current value
   * After UPDATE: increments version by 1
   * If 0 rows updated: OptimisticLockException
   *
   * NEVER set this manually. Hibernate owns it.
   */
  @Version
  @Column(nullable = false)
  private Integer version = 0;

  @Column(name = "created_at", updatable = false)
  private LocalDateTime createdAt = LocalDateTime.now();

  @UpdateTimestamp
  @Column(name = "updated_at")
  private LocalDateTime updatedAt;

  // ── Domain methods ────────────────────────────────────────────────────────

  /**
   * Transition to next status via state machine.
   * Sets completedAt if transitioning to a terminal state.
   * Caller must save() after this.
   */
  public void transitionTo(PaymentStatus next) {
      this.status = this.status.transitionTo(next); // throws if illegal
      if (next.isTerminal()) {
          this.completedAt = LocalDateTime.now();
      }
  }

  /**
   * Is this a high-value payment requiring step-up auth?
   * Threshold defined in application.yml, injected where needed.
   * Domain method uses the threshold passed in — no @Value in entities.
   */
  public boolean isHighValue(BigDecimal threshold) {
      return amount.compareTo(threshold) >= 0;
  }

  public void markFailed(String reason) {
      transitionTo(PaymentStatus.FAILED);
      this.failureReason = reason;
  }

  public void markBlocked(String reason) {
      transitionTo(PaymentStatus.BLOCKED);
      this.failureReason = reason;
  }
}