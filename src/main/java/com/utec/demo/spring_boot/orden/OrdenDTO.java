package com.utec.demo.spring_boot.orden;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

public class OrdenDTO {

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CrearOrdenRequest {
        @NotEmpty(message = "La orden debe tener al menos un detalle")
        @Valid
        private List<CrearDetalleRequest> detalles;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CrearDetalleRequest {
        @NotNull(message = "El ID del producto es obligatorio")
        private Long productoId;

        @NotNull(message = "La cantidad es obligatoria")
        @Positive(message = "La cantidad debe ser mayor a 0")
        private Integer cantidad;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class OrdenResponse {
        private Long id;
        private Long usuarioId;
        private String usuarioNombre;
        private LocalDateTime fecha;
        private Double total;
        private List<DetalleResponse> detalles;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class DetalleResponse {
        private Long id;
        private Long productoId;
        private String productoNombre;
        private Integer cantidad;
        private Double precioUnitario;
        private Double subtotal;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class OrdenSummaryResponse {
        private Long id;
        private LocalDateTime fecha;
        private Double total;
        private Integer cantidadItems;
    }
}
