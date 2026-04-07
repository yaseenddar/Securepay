package com.securepay.transaction.exception;

public class IllegalStateTransitionException extends RuntimeException {

	public IllegalStateTransitionException(String string) {
		// TODO Auto-generated constructor stub

		super("Invalid TOTP code");

	}

}
