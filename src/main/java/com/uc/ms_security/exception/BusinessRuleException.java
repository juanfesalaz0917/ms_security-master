package com.uc.ms_security.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

public class BusinessRuleException extends ResponseStatusException {

    public BusinessRuleException(String message) {
        super(HttpStatus.CONFLICT, message);
    }
}