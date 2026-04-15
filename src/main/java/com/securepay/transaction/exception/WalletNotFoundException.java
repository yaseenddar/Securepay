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
	 public WalletNotFoundException(String string) {
	        super("Wallet not found or  "+ string);
	    }

}
