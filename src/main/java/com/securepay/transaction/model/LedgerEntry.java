package com.securepay.transaction.model;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.UUID;

import com.securepay.transaction.model.LedgerEntry.EntryType;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

//─────────────────────────────────────────────────────────────────────────────
//LEDGER ENTRY — insert only, never update or delete
//─────────────────────────────────────────────────────────────────────────────

/**
* Double-entry ledger record.
*
* IMMUTABLE BY DESIGN:
* - No setters on financial fields (amount, entryType, walletId, paymentId)
* - No @UpdateTimestamp — there is no update
* - No @Version — no concurrent writes to the same row (insert-only)
*
* Every payment generates exactly 2 entries:
* DEBIT  payer_wallet  ₹500
* CREDIT payee_wallet  ₹500
*
* SUM of all DEBIT == SUM of all CREDIT across all entries.
* If they don't: there's a bug. This invariant is checked in reconciliation.
*/
@Entity
@Table(name = "ledger_entries", schema = "txn")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LedgerEntry {

 @Id
 @GeneratedValue(strategy = GenerationType.UUID)
 private UUID id;

 @Column(name = "payment_id", nullable = false, updatable = false)
 private UUID paymentId;

 @Column(name = "wallet_id", nullable = false, updatable = false)
 private UUID walletId;

 @Enumerated(EnumType.STRING)
 @Column(name = "entry_type", nullable = false, updatable = false, length = 6)
 private EntryType entryType;

 @Column(nullable = false, precision = 15, scale = 2, updatable = false)
 private BigDecimal amount;

 @Column(name = "balance_after", nullable = false, updatable = false, precision = 15, scale = 2)
 private BigDecimal balanceAfter;   // snapshot — for quick balance display without SUM

 @Column(updatable = false, length = 255)
 private String description;

 @Column(name = "created_at", updatable = false)
 private LocalDateTime createdAt = LocalDateTime.now();

 public enum EntryType { DEBIT, CREDIT }
}
