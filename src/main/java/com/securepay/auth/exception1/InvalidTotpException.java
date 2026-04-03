package com.securepay.auth.exception1;

public class InvalidTotpException extends Exception {

    private static final long serialVersionUID = 1L;

    public InvalidTotpException() {
        super();
    }

    public InvalidTotpException(String message) {
        super(message);
    }

    public InvalidTotpException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidTotpException(Throwable cause) {
        super(cause);
    }
}
