package com.github.codert96.gateway;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.security.GeneralSecurityException;

@Getter
public class DecryptionFailureException extends GeneralSecurityException {
    private final HttpStatus httpStatus;

    public DecryptionFailureException(HttpStatus httpStatus, Throwable cause) {
        super(httpStatus.getReasonPhrase(), cause);
        this.httpStatus = httpStatus;
    }
}