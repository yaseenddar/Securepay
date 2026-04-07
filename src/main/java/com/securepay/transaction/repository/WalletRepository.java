package com.securepay.transaction.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.securepay.transaction.model.Payment;
import com.securepay.transaction.model.Wallet;

public interface WalletRepository extends JpaRepository<Wallet, UUID>  {

	public Optional<Wallet> findByUserId(UUID payeeUserId);

	public Optional<Wallet> findByUserIdForUpdate(UUID payerUserId);

}
