package com.utec.demo.spring_boot.producto;

import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;

@Service
public class ProductoServiceBD {
    private final ProductoRepository productoRepository;

    public ProductoServiceBD(ProductoRepository productoRepository) {
        this.productoRepository = productoRepository;
    }

    public List<ProductoBD> listarTodos() {
        return productoRepository.findAll();
    }

    public Optional<ProductoBD> obtenerPorId(Long id) {
        return productoRepository.findById(id);
    }

    public ProductoBD guardar(ProductoBD producto) {
        return productoRepository.save(producto);
    }

    public void eliminar(Long id) {
        productoRepository.deleteById(id);
    }
}
