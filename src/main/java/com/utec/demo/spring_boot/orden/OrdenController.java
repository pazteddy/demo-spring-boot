package com.utec.demo.spring_boot.orden;

import com.utec.demo.spring_boot.usuario.Usuario;
import com.utec.demo.spring_boot.usuario.UsuarioService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Controlador REST para gestionar órdenes de usuarios
 *
 * Endpoints disponibles:
 * - POST /api/ordenes - Crear una nueva orden
 * - GET /api/ordenes - Listar órdenes del usuario autenticado
 * - GET /api/ordenes/{id} - Obtener detalle de una orden específica
 */
@RestController
@RequestMapping("/api/ordenes")
@RequiredArgsConstructor
@Slf4j
public class OrdenController {

    private final OrdenService ordenService;
    private final UsuarioService usuarioService;

    /**
     * Crear una nueva orden para el usuario autenticado
     *
     * @param request Datos de la orden a crear
     * @return Orden creada con todos sus detalles
     */
    @PostMapping
    public ResponseEntity<OrdenDTO.OrdenResponse> crearOrden(@Valid @RequestBody OrdenDTO.CrearOrdenRequest request) {
        log.info("Recibida solicitud para crear orden");

        Long usuarioId = obtenerUsuarioAutenticadoId();
        OrdenDTO.OrdenResponse orden = ordenService.crearOrden(usuarioId, request);

        return ResponseEntity.status(HttpStatus.CREATED).body(orden);
    }

    /**
     * Listar todas las órdenes del usuario autenticado
     *
     * @return Lista resumida de órdenes del usuario
     */
    @GetMapping
    public ResponseEntity<List<OrdenDTO.OrdenSummaryResponse>> listarOrdenes() {
        log.info("Recibida solicitud para listar órdenes");

        Long usuarioId = obtenerUsuarioAutenticadoId();
        List<OrdenDTO.OrdenSummaryResponse> ordenes = ordenService.listarOrdenesPorUsuario(usuarioId);

        return ResponseEntity.ok(ordenes);
    }

    /**
     * Obtener el detalle completo de una orden específica
     *
     * @param id ID de la orden a consultar
     * @return Orden con todos sus detalles
     */
    @GetMapping("/{id}")
    public ResponseEntity<OrdenDTO.OrdenResponse> obtenerOrden(@PathVariable Long id) {
        log.info("Recibida solicitud para obtener orden ID: {}", id);

        Long usuarioId = obtenerUsuarioAutenticadoId();
        OrdenDTO.OrdenResponse orden = ordenService.obtenerOrdenPorId(id, usuarioId);

        return ResponseEntity.ok(orden);
    }

    /**
     * Verificar si una orden existe y pertenece al usuario autenticado
     *
     * @param id ID de la orden a verificar
     * @return true si la orden existe y pertenece al usuario
     */
    @GetMapping("/{id}/exists")
    public ResponseEntity<Boolean> verificarOrden(@PathVariable Long id) {
        log.info("Verificando existencia de orden ID: {}", id);

        Long usuarioId = obtenerUsuarioAutenticadoId();
        boolean existe = ordenService.existeOrden(id, usuarioId);

        return ResponseEntity.ok(existe);
    }

    /**
     * Obtener el ID del usuario autenticado desde el contexto de seguridad
     *
     * @return ID del usuario autenticado
     * @throws RuntimeException si no hay usuario autenticado
     */
    private Long obtenerUsuarioAutenticadoId() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new RuntimeException("Usuario no autenticado");
        }

        String username = authentication.getName();
        Usuario usuario = usuarioService.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado: " + username));

        return usuario.getId();
    }
}
