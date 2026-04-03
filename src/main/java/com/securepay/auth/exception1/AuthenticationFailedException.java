package com.securepay.auth.exception1;

public class AuthenticationFailedException extends Exception {

    private static final long serialVersionUID = 1L;

    // Default constructor
    public AuthenticationFailedException() {
        super();
    }

    // Constructor with message
    public AuthenticationFailedException(String message) {
        super(message);
    }

    // Constructor with message and cause
    public AuthenticationFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    // Constructor with cause
    public AuthenticationFailedException(Throwable cause) {
        super(cause);
    }
}