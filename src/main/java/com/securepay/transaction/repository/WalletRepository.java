package com.securepay.transaction.repository;

import java.util.Optional;
import java.util.UUID;

import jakarta.persistence.LockModeType;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.securepay.transaction.model.Payment;
import com.securepay.transaction.model.Wallet;
@Repository
public interface WalletRepository extends JpaRepository<Wallet, UUID> {

	Optional<Wallet> findByUserId(UUID userId);

	@Lock(LockModeType.PESSIMISTIC_WRITE)
	@Query("select w from Wallet w where w.userId = :userId")
	Optional<Wallet> findByUserIdForUpdate(@Param("userId") UUID userId);
	
	@Lock(LockModeType.PESSIMISTIC_WRITE)
	@Query("select w from Wallet w where w.userId = :userId")
	Optional<Payment> findByUserId(String payeeVpa);
}
