package com.utec.demo.spring_boot.config;

import com.utec.demo.spring_boot.auth.AuthDTO;
import com.utec.demo.spring_boot.auth.AuthException;
import com.utec.demo.spring_boot.orden.OrdenException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthException.UserAlreadyExistsException.class)
    public ResponseEntity<AuthDTO.ErrorResponse> handleUserAlreadyExists(AuthException.UserAlreadyExistsException e) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new AuthDTO.ErrorResponse("USER_ALREADY_EXISTS", e.getMessage(), 409));
    }

    @ExceptionHandler(AuthException.InvalidCredentialsException.class)
    public ResponseEntity<AuthDTO.ErrorResponse> handleInvalidCredentials(AuthException.InvalidCredentialsException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new AuthDTO.ErrorResponse("INVALID_CREDENTIALS", e.getMessage(), 401));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        return ResponseEntity.badRequest().body(errors);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<AuthDTO.ErrorResponse> handleGenericException(Exception e) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new AuthDTO.ErrorResponse("INTERNAL_ERROR", "Error interno del servidor", 500));
    }

    // Manejo de excepciones de órdenes
    @ExceptionHandler(OrdenException.OrdenNoEncontradaException.class)
    public ResponseEntity<AuthDTO.ErrorResponse> handleOrdenNoEncontrada(OrdenException.OrdenNoEncontradaException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new AuthDTO.ErrorResponse("ORDEN_NOT_FOUND", e.getMessage(), 404));
    }

    @ExceptionHandler(OrdenException.StockInsuficienteException.class)
    public ResponseEntity<AuthDTO.ErrorResponse> handleStockInsuficiente(OrdenException.StockInsuficienteException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new AuthDTO.ErrorResponse("INSUFFICIENT_STOCK", e.getMessage(), 400));
    }

    @ExceptionHandler(OrdenException.ProductoNoEncontradoException.class)
    public ResponseEntity<AuthDTO.ErrorResponse> handleProductoNoEncontrado(OrdenException.ProductoNoEncontradoException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new AuthDTO.ErrorResponse("PRODUCT_NOT_FOUND", e.getMessage(), 404));
    }

    @ExceptionHandler(OrdenException.AccesoNoAutorizadoException.class)
    public ResponseEntity<AuthDTO.ErrorResponse> handleAccesoNoAutorizado(OrdenException.AccesoNoAutorizadoException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new AuthDTO.ErrorResponse("ACCESS_DENIED", e.getMessage(), 403));
    }

    @ExceptionHandler(OrdenException.OrdenVaciaException.class)
    public ResponseEntity<AuthDTO.ErrorResponse> handleOrdenVacia(OrdenException.OrdenVaciaException e) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new AuthDTO.ErrorResponse("EMPTY_ORDER", e.getMessage(), 400));
    }
}
