package com.utec.demo.spring_boot.controllers;

import com.utec.demo.spring_boot.auth.AuthDTO;
import com.utec.demo.spring_boot.auth.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthDTO.AuthResponse> register(@Valid @RequestBody AuthDTO.RegisterRequest request) {
        AuthDTO.AuthResponse response = authService.register(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthDTO.AuthResponse> authenticate(@Valid @RequestBody AuthDTO.LoginRequest request) {
        AuthDTO.AuthResponse response = authService.authenticate(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/public")
    public ResponseEntity<String> publicEndpoint() {
        return ResponseEntity.ok("Esta es una ruta pública - accesible sin autenticación");
    }
}