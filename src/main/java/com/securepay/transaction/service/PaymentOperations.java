package com.securepay.transaction.service;

import com.securepay.transaction.dto.PaymentRequest;
import com.securepay.transaction.dto.PaymentResponse;
import com.securepay.transaction.exception.InsufficientFundsException;

import java.util.UUID;

/**
 * Application API for payment flows (implemented by {@link PaymentService} in {@code Service.java}).
 */
public interface PaymentOperations {

    PaymentResponse initiatePayment(PaymentRequest request, AuthContext auth) throws InsufficientFundsException;

    PaymentResponse processPayment(UUID paymentId) throws InsufficientFundsException;

    PaymentResponse getPayment(UUID paymentId, AuthContext auth);

    PaymentResponse reversePayment(UUID paymentId, String reason, AuthContext auth)
            throws InsufficientFundsException;
}
