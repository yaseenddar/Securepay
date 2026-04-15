package com.securepay.auth.exception;

public class TokenRevokedException extends RuntimeException {
    public TokenRevokedException() {
        super("Session revoked or expired");
    }
}
