package com.utec.demo.spring_boot.controllers;

import com.utec.demo.spring_boot.usuario.Usuario;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/usuarios")
@RequiredArgsConstructor
public class UsuarioController {

    @GetMapping("/perfil")
    public ResponseEntity<?> getPerfil() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !(authentication.getPrincipal() instanceof Usuario usuario)) {
            return ResponseEntity.status(401).body("No autenticado correctamente");
        }

        return ResponseEntity.ok(new PerfilResponse(
                usuario.getId(),
                usuario.getUsername(),
                usuario.getEmail(),
                usuario.getRole().name()
        ));
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> adminEndpoint() {
        return ResponseEntity.ok("Esta es una ruta de administrador - solo accesible por ADMIN");
    }

    @GetMapping("/test-protected")
    public ResponseEntity<String> testProtected() {
        return ResponseEntity.ok("Ruta protegida - accesible por cualquier usuario autenticado");
    }

    public record PerfilResponse(Long id, String username, String email, String role) {}
}
