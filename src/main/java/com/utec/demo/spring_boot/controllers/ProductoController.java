package com.utec.demo.spring_boot.controllers;

import com.utec.demo.spring_boot.producto.Producto;
import com.utec.demo.spring_boot.producto.ProductoDTO;
import com.utec.demo.spring_boot.producto.ProductoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;


@RestController
@RequestMapping("/api/productos")
public class ProductoController {
    private final ProductoService productoService;

    @Autowired
    public ProductoController(ProductoService productoService) {
        this.productoService = productoService;
    }
    @GetMapping
    public List<Producto> listarProductos()
    {
        return productoService.listar();
    }
    @PostMapping
    public Producto crearProducto(@RequestBody ProductoDTO productoDto) {
       return productoService.crear(productoDto);
    }
    @GetMapping("/{id}") // http://localhost:8080/api/productos/2
    public Producto obtenerProducto(@PathVariable Long id)
    {
        return productoService.obtenerPorId(id);
    }
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> eliminarProducto(@PathVariable Long id)
    {
        boolean notaEliminada = productoService.eliminar(id);
        if(notaEliminada)
        {
            return ResponseEntity.noContent().build();
        }
        else {
           return ResponseEntity.notFound().build();
        }
    }
}
