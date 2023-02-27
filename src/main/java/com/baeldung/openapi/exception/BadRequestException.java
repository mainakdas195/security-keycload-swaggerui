package com.baeldung.openapi.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value= HttpStatus.BAD_REQUEST)
public class BadRequestException extends RuntimeException {
	private static final long serialVersionUID = -6958128182491079251L;

	public BadRequestException() {
		super();
	}

	private String errorCode;
	private String errorMessage;

	public BadRequestException(String value, String message) {
		this.errorCode = value;
		this.errorMessage = message;
	}

	public String getErrorCode() {
		return errorCode;
	}

	public String getMessage() {
		return this.errorMessage;
	}

}
