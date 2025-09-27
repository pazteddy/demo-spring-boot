package com.utec.demo.spring_boot.orden;

import com.utec.demo.spring_boot.producto.ProductoBD;
import com.utec.demo.spring_boot.producto.ProductoRepository;
import com.utec.demo.spring_boot.usuario.Usuario;
import com.utec.demo.spring_boot.usuario.UsuarioRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class OrdenService {

    private final OrdenRepository ordenRepository;
    private final OrdenDetalleRepository ordenDetalleRepository;
    private final ProductoRepository productoRepository;
    private final UsuarioRepository usuarioRepository;

    @Transactional
    public OrdenDTO.OrdenResponse crearOrden(Long usuarioId, OrdenDTO.CrearOrdenRequest request) {
        log.info("Creando orden para usuario ID: {}", usuarioId);

        // Validar que la orden no esté vacía
        if (request.getDetalles() == null || request.getDetalles().isEmpty()) {
            throw new OrdenException.OrdenVaciaException();
        }

        // Buscar el usuario
        Usuario usuario = usuarioRepository.findById(usuarioId)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // Crear la orden
        Orden orden = new Orden();
        orden.setUsuario(usuario);

        // Guardar la orden primero para obtener el ID
        orden = ordenRepository.save(orden);

        // Guardar el ID para usar en lambda
        final Long ordenId = orden.getId();

        // Procesar cada detalle
        for (OrdenDTO.CrearDetalleRequest detalleRequest : request.getDetalles()) {
            OrdenDetalle detalle = agregarDetalle(orden, detalleRequest);
            // Agregar el detalle a la lista de la orden
            orden.getDetalles().add(detalle);
        }

        // Guardar la orden actualizada con los detalles
        orden = ordenRepository.save(orden);

        // Recargar la orden con los detalles para asegurar que estén cargados
        Orden ordenCompleta = ordenRepository.findByIdAndUsuarioIdWithDetalles(ordenId, usuarioId)
                .orElseThrow(() -> new OrdenException.OrdenNoEncontradaException(ordenId));

        log.info("Orden creada exitosamente con ID: {} y {} detalles", ordenCompleta.getId(),
                ordenCompleta.getDetalles().size());
        return convertirAOrdenResponse(ordenCompleta);
    }

    @Transactional
    private OrdenDetalle agregarDetalle(Orden orden, OrdenDTO.CrearDetalleRequest detalleRequest) {
        log.info("Agregando detalle: producto {} cantidad {}", detalleRequest.getProductoId(),
                detalleRequest.getCantidad());

        // Buscar el producto
        ProductoBD producto = productoRepository.findById(detalleRequest.getProductoId())
                .orElseThrow(() -> new OrdenException.ProductoNoEncontradoException(detalleRequest.getProductoId()));

        // Validar stock suficiente
        if (producto.getStock() < detalleRequest.getCantidad()) {
            throw new OrdenException.StockInsuficienteException(
                    producto.getTitle(),
                    producto.getStock(),
                    detalleRequest.getCantidad());
        }

        // Crear el detalle
        OrdenDetalle detalle = new OrdenDetalle();
        detalle.setOrden(orden);
        detalle.setProducto(producto);
        detalle.setCantidad(detalleRequest.getCantidad());
        detalle.setPrecioUnitario(producto.getPrice());

        // Guardar el detalle
        detalle = ordenDetalleRepository.save(detalle);

        // Actualizar el stock del producto
        producto.setStock(producto.getStock() - detalleRequest.getCantidad());
        productoRepository.save(producto);

        log.info("Detalle agregado: {} unidades de {} a precio {}",
                detalleRequest.getCantidad(), producto.getTitle(), producto.getPrice());

        return detalle;
    }

    @Transactional(readOnly = true)
    public List<OrdenDTO.OrdenSummaryResponse> listarOrdenesPorUsuario(Long usuarioId) {
        log.info("Listando órdenes para usuario ID: {}", usuarioId);

        List<Orden> ordenes = ordenRepository.findByUsuarioIdWithDetalles(usuarioId);

        return ordenes.stream()
                .map(this::convertirAOrdenSummary)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public OrdenDTO.OrdenResponse obtenerOrdenPorId(Long ordenId, Long usuarioId) {
        log.info("Obteniendo orden ID: {} para usuario ID: {}", ordenId, usuarioId);

        Orden orden = ordenRepository.findByIdAndUsuarioIdWithDetalles(ordenId, usuarioId)
                .orElseThrow(() -> new OrdenException.OrdenNoEncontradaException(ordenId));

        return convertirAOrdenResponse(orden);
    }

    @Transactional(readOnly = true)
    public boolean existeOrden(Long ordenId, Long usuarioId) {
        return ordenRepository.findByIdAndUsuarioId(ordenId, usuarioId).isPresent();
    }

    // Métodos de conversión
    private OrdenDTO.OrdenResponse convertirAOrdenResponse(Orden orden) {
        List<OrdenDTO.DetalleResponse> detalles = orden.getDetalles().stream()
                .map(this::convertirADetalleResponse)
                .collect(Collectors.toList());

        return new OrdenDTO.OrdenResponse(
                orden.getId(),
                orden.getUsuario().getId(),
                orden.getUsuario().getUsername(),
                orden.getFecha(),
                orden.getTotal(),
                detalles);
    }

    private OrdenDTO.DetalleResponse convertirADetalleResponse(OrdenDetalle detalle) {
        return new OrdenDTO.DetalleResponse(
                detalle.getId(),
                detalle.getProducto().getId(),
                detalle.getProducto().getTitle(),
                detalle.getCantidad(),
                detalle.getPrecioUnitario(),
                detalle.getSubtotal());
    }

    private OrdenDTO.OrdenSummaryResponse convertirAOrdenSummary(Orden orden) {
        // Calcular la cantidad total de items sumando las cantidades de cada detalle
        Integer cantidadTotalItems = orden.getDetalles().stream()
                .mapToInt(OrdenDetalle::getCantidad)
                .sum();

        return new OrdenDTO.OrdenSummaryResponse(
                orden.getId(),
                orden.getFecha(),
                orden.getTotal(),
                cantidadTotalItems);
    }
}
