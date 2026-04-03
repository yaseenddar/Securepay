package com.securepay.auth.exception1;

public class TokenRevokedException extends Exception {

    private static final long serialVersionUID = 1L;

    public TokenRevokedException() {
        super();
    }

    public TokenRevokedException(String message) {
        super(message);
    }

    public TokenRevokedException(String message, Throwable cause) {
        super(message, cause);
    }

    public TokenRevokedException(Throwable cause) {
        super(cause);
    }
}