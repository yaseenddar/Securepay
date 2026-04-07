package com.securepay.transaction.model;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

import org.hibernate.annotations.UpdateTimestamp;

import com.securepay.transaction.exception.InsufficientFundsException;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

//─────────────────────────────────────────────────────────────────────────────
//WALLET ENTITY
//─────────────────────────────────────────────────────────────────────────────

/**
* Materialized wallet balance.
*
* NO @Version here — wallet uses SELECT FOR UPDATE instead.
* WHY pessimistic over optimistic?
* Balance deduction is high-contention: a user could initiate multiple
* payments simultaneously (or an attacker could). Optimistic locking would
* cause frequent OptimisticLockException → retries → thundering herd.
* SELECT FOR UPDATE serializes balance writes — one at a time, no retries.
*
* Balance is kept consistent with ledger_entries by always:
* 1. SELECT wallet FOR UPDATE
* 2. INSERT ledger entry
* 3. UPDATE wallet balance
* All in one transaction. Atomically.
*/
@Entity
@Table(name = "wallets", schema = "txn")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
 public class Wallet {

 @Id
 @GeneratedValue(strategy = GenerationType.UUID)
 private UUID id;

 @Column(name = "user_id", nullable = false, unique = true)
 private UUID userId;

 @Column(nullable = false, precision = 15, scale = 2)
 private BigDecimal balance = BigDecimal.ZERO;

 @Column(nullable = false, length = 3)
 private String currency = "INR";

 @Column(name = "is_active", nullable = false)
 private boolean isActive = true;

 @Column(name = "created_at", updatable = false)
 private LocalDateTime createdAt = LocalDateTime.now();

 @UpdateTimestamp
 @Column(name = "updated_at")
 private LocalDateTime updatedAt;

 // ── Domain methods ────────────────────────────────────────────────────────

 /**
  * Deduct amount from balance.
  * Called ONLY after SELECT FOR UPDATE — never without the lock.
  * Throws if insufficient funds — DB CHECK constraint also enforces this.
  * @throws InsufficientFundsException 
  */
 public void deduct(BigDecimal amount) throws InsufficientFundsException {
     if (this.balance.compareTo(amount) < 0) {
         throw new com.securepay.transaction.exception.InsufficientFundsException(
                 "Balance " + this.balance + " insufficient for deduction of " + amount
         );
     }
     this.balance = this.balance.subtract(amount);
 }

 /**
  * Credit amount to balance.
  * No lock required for credits — adding money doesn't need serialization.
  * (Though in practice we still use the same transaction for atomicity.)
  */
 public void credit(BigDecimal amount) {
     this.balance = this.balance.add(amount);
 }

 public boolean hasSufficientBalance(BigDecimal amount) {
     return this.balance.compareTo(amount) >= 0;
 }
}
