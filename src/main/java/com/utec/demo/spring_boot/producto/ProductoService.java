package com.utec.demo.spring_boot.producto;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

@Service
public class ProductoService {
    // Aquí puedes implementar la lógica de negocio relacionada con los productos
    private static final List<Producto> BD = new ArrayList<>();
    private static final AtomicLong NEXT_ID = new AtomicLong(1L);
    public List<Producto> listar()
    {
        return BD;
    }
    public Producto crear(ProductoDTO productoDto) {
        Producto nuevoProducto = new Producto(
                NEXT_ID.getAndIncrement(),
                productoDto.getNombre(),
                productoDto.getPrecio());
        BD.add(nuevoProducto);
        return nuevoProducto;
    }
    public Producto obtenerPorId(Long id)
    {
        return BD.stream()
                .filter(p -> p.getId()
                        .equals(id))
                .findFirst()
                .orElseThrow(() -> new ProductoNoEncontradoException(id));
    }
    public boolean eliminar(Long id)
    {
        boolean productoEliminado =  BD.removeIf(p -> p.getId().equals(id));
        if(!productoEliminado)
        {
            throw new ProductoNoEncontradoException(id);
        }
        return productoEliminado;
    }

}
