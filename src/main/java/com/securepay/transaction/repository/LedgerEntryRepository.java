package com.securepay.transaction.repository;

import java.math.BigDecimal;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.securepay.transaction.model.LedgerEntry;
import com.securepay.transaction.model.Payment;

public interface LedgerEntryRepository extends JpaRepository<LedgerEntry, UUID> {

	BigDecimal computeBalanceFromLedger(UUID walletId);

	
}
