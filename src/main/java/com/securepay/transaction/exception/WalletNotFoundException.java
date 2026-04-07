package com.securepay.transaction.exception;

import java.util.UUID;

public class WalletNotFoundException  extends RuntimeException  {

	/**
	 * 
	 */
	private static final long serialVersionUID = -1897454158479157349L;
	/**
	 * 
	 */
	 public WalletNotFoundException(UUID uuid) {
	        super("Wallet not found "+ uuid);
	    }

}
