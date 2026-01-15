package com.operationly.apigateway.exception;

import lombok.Getter;

@Getter
public class BusinessException extends RuntimeException {

    public static final String BUSINESS_EXCEPTION = "BUSINESS_EXCEPTION";
    private final String errorCode;
    private final String errorMessage;

    public BusinessException(String errorMessage) {
        super(errorMessage);
        this.errorCode = BUSINESS_EXCEPTION;
        this.errorMessage = errorMessage;
    }

    public BusinessException(String errorMessage, Exception exception) {
        super(exception);
        this.errorCode = BUSINESS_EXCEPTION;
        this.errorMessage = errorMessage;
    }

    public BusinessException(String errorCode, String errorMessage) {
        super(errorMessage);
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
    }

    public BusinessException(String errorCode, String errorMessage, Throwable cause) {
        super(cause);
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
    }

    public BusinessException(String errorMessage, Error error) {
        super(error);
        this.errorCode = BUSINESS_EXCEPTION;
        this.errorMessage = errorMessage;
    }
}
