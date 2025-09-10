package com.utec.demo.spring_boot.controllers;

import com.utec.demo.spring_boot.producto.Producto;
import com.utec.demo.spring_boot.producto.ProductoDTO;
import org.springframework.web.bind.annotation.*;
import java.util.List;


@RestController
@RequestMapping("/api/productos")
public class ProductoController {
    @GetMapping
    public List<Producto> listarProductos()
    {
        return List.of(
                new Producto(1L, "Producto A", 25.0),
                new Producto(2L, "Producto B", 40.0),
                new Producto(3L, "Producto C", 200.0)
        );
    }
    @PostMapping
    public Producto crearProducto(@RequestBody ProductoDTO productoDto) {
       System.out.println("Producto recibido: "
                          + productoDto.getNombre()+
                          ", Precio: "+productoDto.getPrecio());
       return new Producto(4L, productoDto.getNombre(),productoDto.getPrecio());
    }
    @GetMapping("/{id}")
    public Producto obtenerProducto(@PathVariable Long id)
    {
        return new Producto(1L, "Producto A", 25.0);
    }
}
