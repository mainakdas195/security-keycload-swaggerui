package com.baeldung.openapi.exception.handler;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.baeldung.openapi.exception.BadRequestException;
import com.baeldung.openapi.exception.ExceptionResponse;

@ControllerAdvice
@RestController
public class CustomizedResponseEntityExceptionHandler extends ResponseEntityExceptionHandler{

	
	
	@ExceptionHandler(BadRequestException.class)
	@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
	public final ResponseEntity<ExceptionResponse> handleAllException(BadRequestException ex, WebRequest request){
		ExceptionResponse expResp =  new ExceptionResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(), ex.getErrorCode(), ex.getMessage());
		return new ResponseEntity(expResp, HttpStatus.INTERNAL_SERVER_ERROR);
	}
	

}
