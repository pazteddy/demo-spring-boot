package com.utec.demo.spring_boot.controllers;

import com.utec.demo.spring_boot.producto.Producto;
import com.utec.demo.spring_boot.producto.ProductoDTO;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;


@RestController
@RequestMapping("/api/productos")
public class ProductoController {
    private static final List<Producto> BD = new ArrayList<>();
    private static final AtomicLong NEXT_ID = new AtomicLong(1L);
    @GetMapping
    public List<Producto> listarProductos()
    {
        return BD;
    }
    @PostMapping
    public Producto crearProducto(@RequestBody ProductoDTO productoDto) {
       Producto nuevoProducto = new Producto(
                                NEXT_ID.getAndIncrement(),
                                productoDto.getNombre(),
                                productoDto.getPrecio());
       BD.add(nuevoProducto);
       return nuevoProducto;
    }
    @GetMapping("/{id}") // http://localhost:8080/api/productos/2
    public Producto obtenerProducto(@PathVariable Long id)
    {
        return BD.stream()
                 .filter(p -> p.getId()
                 .equals(id))
                 .findFirst()
                 .orElse(null);
    }
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> eliminarProducto(@PathVariable Long id)
    {
        boolean notaEliminada = BD.removeIf(p -> p.getId().equals(id));
        if(notaEliminada)
        {
            return ResponseEntity.noContent().build();
        }
        else {
           return ResponseEntity.notFound().build();
        }
    }
}
