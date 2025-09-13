package com.utec.demo.spring_boot.orden;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface OrdenDetalleRepository extends JpaRepository<OrdenDetalle, Long> {

    // Buscar detalles por orden
    List<OrdenDetalle> findByOrdenId(Long ordenId);

    // Buscar detalles por producto
    List<OrdenDetalle> findByProductoId(Long productoId);

    // Buscar detalles con información del producto
    @Query("SELECT od FROM OrdenDetalle od LEFT JOIN FETCH od.producto WHERE od.orden.id = :ordenId")
    List<OrdenDetalle> findByOrdenIdWithProducto(@Param("ordenId") Long ordenId);

    // Calcular total vendido de un producto
    @Query("SELECT COALESCE(SUM(od.cantidad), 0) FROM OrdenDetalle od WHERE od.producto.id = :productoId")
    Long getTotalVendidoByProductoId(@Param("productoId") Long productoId);
}
