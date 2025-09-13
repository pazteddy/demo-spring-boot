package com.utec.demo.spring_boot.orden;

public class OrdenException extends RuntimeException {

    public OrdenException(String message) {
        super(message);
    }

    public OrdenException(String message, Throwable cause) {
        super(message, cause);
    }

    public static class OrdenNoEncontradaException extends OrdenException {
        public OrdenNoEncontradaException(Long id) {
            super("Orden no encontrada con ID: " + id);
        }
    }

    public static class StockInsuficienteException extends OrdenException {
        public StockInsuficienteException(String producto, Integer stockDisponible, Integer cantidadSolicitada) {
            super(String.format("Stock insuficiente para el producto '%s'. Stock disponible: %d, cantidad solicitada: %d",
                    producto, stockDisponible, cantidadSolicitada));
        }
    }

    public static class ProductoNoEncontradoException extends OrdenException {
        public ProductoNoEncontradoException(Long productoId) {
            super("Producto no encontrado con ID: " + productoId);
        }
    }

    public static class AccesoNoAutorizadoException extends OrdenException {
        public AccesoNoAutorizadoException() {
            super("No tienes permisos para acceder a esta orden");
        }
    }

    public static class OrdenVaciaException extends OrdenException {
        public OrdenVaciaException() {
            super("La orden debe tener al menos un producto");
        }
    }
}
