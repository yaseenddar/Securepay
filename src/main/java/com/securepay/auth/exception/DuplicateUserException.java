package com.securepay.auth.exception;

public class DuplicateUserException extends RuntimeException {
    public DuplicateUserException(String field) {
        super("Duplicate " + field);
    }
}
