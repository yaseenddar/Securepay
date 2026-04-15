package com.securepay.transaction.exception;

import java.util.UUID;

public class PaymentNotFoundException extends RuntimeException  {
	 
	/**
	 * 
	 */
	private static final long serialVersionUID = -6989865753479131050L;

	public PaymentNotFoundException(UUID paymentId) {
		super("Payment not found: " + paymentId);
	}
}
