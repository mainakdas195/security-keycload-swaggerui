package com.baeldung.openapi.exception;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ExceptionResponse {
	private int statusCode;
	private String errorCode;
    private String message;
    
	public ExceptionResponse(int statusCode, String errorCode, String message) {
		super();
		this.statusCode = statusCode;
		this.errorCode = errorCode;
		this.message = message;
	}

	public int getStatusCode() {
		return statusCode;
	}

	public void setStatusCode(int statusCode) {
		this.statusCode = statusCode;
	}

	public String getErrorCode() {
		return errorCode;
	}

	public void setErrorCode(String errorCode) {
		this.errorCode = errorCode;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}
	
	
    
    
}
