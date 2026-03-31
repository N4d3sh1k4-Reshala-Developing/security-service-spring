package com.n4d3sh1k4.security_service.exception;

import com.n4d3sh1k4.security_service.dto.exception_dto.ApiError;
import com.n4d3sh1k4.security_service.dto.exception_dto.ErrorCode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ApiError> handleUserAlreadyExists(UserAlreadyExistsException ex) {
        return buildResponse(HttpStatus.CONFLICT, ErrorCode.USER_ALREADY_EXISTS, ex.getMessage());
    }

    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<ApiError> handleNotFound(NoSuchElementException ex) {
        return buildResponse(HttpStatus.NOT_FOUND, ErrorCode.USER_NOT_FOUND, ex.getMessage());
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ApiError> handleBadCredentials(BadCredentialsException ex) {
        return buildResponse(HttpStatus.UNAUTHORIZED, ErrorCode.INVALID_CREDENTIALS, ex.getMessage());
    }

    @ExceptionHandler(TokenNotFoundException.class)
    public ResponseEntity<ApiError> tokenNotFound(TokenNotFoundException ex) {
        return buildResponse(HttpStatus.NOT_FOUND, ErrorCode.TOKEN_NOT_FOUND, ex.getMessage());
    }

    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<ApiError> tokenException(TokenExpiredException ex) {
        return buildResponse(HttpStatus.GONE, ErrorCode.TOKEN_EXPIRED, ex.getMessage());
    }

    @ExceptionHandler(ServerErrorException.class)
    public ResponseEntity<ApiError> serverErrorException(ServerErrorException ex) {
        return buildResponse(HttpStatus.SERVICE_UNAVAILABLE, ErrorCode.INTERNAL_ERROR, ex.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiError> handleMethodArgumentNotValid(Exception ex) {
        if (ex instanceof MethodArgumentNotValidException validEx) {
            String msg = validEx.getBindingResult().getAllErrors().getFirst().getDefaultMessage();
            return buildResponse(HttpStatus.UNPROCESSABLE_ENTITY, ErrorCode.VALIDATION_ERROR, msg);
        }
        return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL_ERROR, "Unknown error");
    }

    @ExceptionHandler(TooManyRequestsException.class)
    public ResponseEntity<ApiError> TooManyRequestsException(TooManyRequestsException ex) {
        return buildResponse(HttpStatus.TOO_MANY_REQUESTS, ErrorCode.INTERNAL_ERROR, ex.getMessage());
    }

    private ResponseEntity<ApiError> buildResponse(HttpStatus status, ErrorCode code, String message) {
        return new ResponseEntity<>(new ApiError(
                status.value(),
                code.name(),
                (message != null && !message.isEmpty()) ? message : code.getDefaultMessage(),
                LocalDateTime.now()
        ), status);
    }
}
