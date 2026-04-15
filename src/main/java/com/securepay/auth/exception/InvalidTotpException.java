package com.securepay.auth.exception;

public class InvalidTotpException extends RuntimeException {
    public InvalidTotpException() {
        super("Invalid TOTP code");
    }
}
