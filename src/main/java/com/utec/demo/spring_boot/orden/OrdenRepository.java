package com.utec.demo.spring_boot.orden;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OrdenRepository extends JpaRepository<Orden, Long> {

    // Buscar órdenes por usuario
    List<Orden> findByUsuarioIdOrderByFechaDesc(Long usuarioId);

    // Buscar una orden específica por ID y usuario (para seguridad)
    Optional<Orden> findByIdAndUsuarioId(Long id, Long usuarioId);

    // Contar órdenes por usuario
    long countByUsuarioId(Long usuarioId);

    // Buscar órdenes con sus detalles (para evitar lazy loading issues)
    @Query("SELECT o FROM Orden o LEFT JOIN FETCH o.detalles WHERE o.usuario.id = :usuarioId ORDER BY o.fecha DESC")
    List<Orden> findByUsuarioIdWithDetalles(@Param("usuarioId") Long usuarioId);

    // Buscar una orden con sus detalles
    @Query("SELECT o FROM Orden o LEFT JOIN FETCH o.detalles WHERE o.id = :id AND o.usuario.id = :usuarioId")
    Optional<Orden> findByIdAndUsuarioIdWithDetalles(@Param("id") Long id, @Param("usuarioId") Long usuarioId);
}
