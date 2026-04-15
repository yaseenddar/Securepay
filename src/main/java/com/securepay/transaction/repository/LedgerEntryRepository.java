package com.securepay.transaction.repository;

import java.math.BigDecimal;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.securepay.transaction.model.LedgerEntry;

public interface LedgerEntryRepository extends JpaRepository<LedgerEntry, UUID> {

	@Query(value = """
			select coalesce(sum(case when entry_type = 'CREDIT' then amount
			                         when entry_type = 'DEBIT' then -amount
			                         else 0 end), 0)
			from txn.ledger_entries where wallet_id = :walletId
			""", nativeQuery = true)
	BigDecimal computeBalanceFromLedger(@Param("walletId") UUID walletId);
}
