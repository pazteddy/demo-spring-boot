package com.utec.demo.spring_boot.controllers;
import com.utec.demo.spring_boot.producto.ProductoBD;
import com.utec.demo.spring_boot.producto.ProductoServiceBD;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/productosBD") // Esto viene de los productos de la base de datos
public class ProductoControllerBD {
    private final ProductoServiceBD productoService;

    public ProductoControllerBD(ProductoServiceBD productoService) {
        this.productoService = productoService;
    }

    @GetMapping
    public List<ProductoBD> listar() {
        return productoService.listarTodos();
    }

    @GetMapping("/{id}")
    public ResponseEntity<ProductoBD> obtener(@PathVariable Long id) {
        return productoService.obtenerPorId(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ProductoBD crear(@RequestBody ProductoBD producto) {
        return productoService.guardar(producto);
    }

    @PutMapping("/{id}")
    public ResponseEntity<ProductoBD> actualizar(@PathVariable Long id,
                                                 @RequestBody ProductoBD producto) {
        return productoService.obtenerPorId(id)
                .map(p -> {
                    producto.setId(id);
                    return ResponseEntity.ok(productoService.guardar(producto));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> eliminar(@PathVariable Long id) {
        if (productoService.obtenerPorId(id).isPresent()) {
            productoService.eliminar(id);
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.notFound().build();
    }
}
