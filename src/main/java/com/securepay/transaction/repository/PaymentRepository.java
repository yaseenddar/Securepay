package com.securepay.transaction.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.securepay.transaction.model.Payment;

public interface PaymentRepository extends JpaRepository<Payment, UUID> {

	Optional<Payment> findByIdempotencyKey(String idempotencyKey);

}
