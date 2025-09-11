# Guía paso a paso: Integrar JPA, Hibernate y PostgreSQL en tu proyecto Spring Boot

Este README te guiará para conectar tu proyecto Spring Boot con PostgreSQL usando JPA/Hibernate y crear un CRUD completo para la entidad `Producto`.

---

## 1. Agregar dependencias en `pom.xml`

Asegúrate de tener las siguientes dependencias en tu `pom.xml`:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-jpa</artifactId>
</dependency>
<dependency>
    <groupId>org.postgresql</groupId>
    <artifactId>postgresql</artifactId>
    <scope>runtime</scope>
</dependency>
```

---

## 2. Configurar la conexión a PostgreSQL

Edita el archivo `src/main/resources/application.properties`:

```
spring.datasource.url=jdbc:postgresql://localhost:5432/tu_basededatos
spring.datasource.username=tu_usuario
spring.datasource.password=tu_contraseña
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=true
spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.PostgreSQLDialect
```

Cambia los valores según tu entorno.

---

## 3. Crear la entidad `Producto`

Crea o edita el archivo `Producto.java` en el paquete `producto`:

```java
package com.utec.demo.spring_boot.producto;

import jakarta.persistence.*;

@Entity
@Table(name = "productos")
public class Producto {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String nombre;
    private Double precio;
    private Integer stock;

    // Getters y setters
}
```

---

## 4. Crear el repositorio JPA

Crea la interfaz `ProductoRepository.java` en el paquete `producto`:

```java
package com.utec.demo.spring_boot.producto;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductoRepository extends JpaRepository<Producto, Long> {
}
```

---

## 5. Crear el servicio para productos

Edita o crea `ProductoService.java`:

```java
package com.utec.demo.spring_boot.producto;

import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;

@Service
public class ProductoService {
    private final ProductoRepository productoRepository;

    public ProductoService(ProductoRepository productoRepository) {
        this.productoRepository = productoRepository;
    }

    public List<Producto> listarTodos() {
        return productoRepository.findAll();
    }

    public Optional<Producto> obtenerPorId(Long id) {
        return productoRepository.findById(id);
    }

    public Producto guardar(Producto producto) {
        return productoRepository.save(producto);
    }

    public void eliminar(Long id) {
        productoRepository.deleteById(id);
    }
}
```

---

## 6. Crear el controlador REST

Edita o crea `ProductoController.java`:

```java
package com.utec.demo.spring_boot.controllers;

import com.utec.demo.spring_boot.producto.Producto;
import com.utec.demo.spring_boot.producto.ProductoService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/productos")
public class ProductoController {
    private final ProductoService productoService;

    public ProductoController(ProductoService productoService) {
        this.productoService = productoService;
    }

    @GetMapping
    public List<Producto> listar() {
        return productoService.listarTodos();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Producto> obtener(@PathVariable Long id) {
        return productoService.obtenerPorId(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public Producto crear(@RequestBody Producto producto) {
        return productoService.guardar(producto);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Producto> actualizar(@PathVariable Long id, @RequestBody Producto producto) {
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
```

---

## 7. Crear la tabla en PostgreSQL

Puedes dejar que Hibernate la cree automáticamente (`ddl-auto=update`) o crearla manualmente:

```sql
CREATE TABLE productos (
    id SERIAL PRIMARY KEY,
    nombre VARCHAR(255),
    precio NUMERIC(10,2),
    stock INTEGER
);
```

---

## 8. Probar el CRUD

- Levanta tu aplicación: `./mvnw spring-boot:run`
- Usa Postman, curl o similar para probar los endpoints:
    - `GET /api/productos`
    - `GET /api/productos/{id}`
    - `POST /api/productos`
    - `PUT /api/productos/{id}`
    - `DELETE /api/productos/{id}`

---

¡Listo! Ahora tienes un CRUD completo con JPA, Hibernate y PostgreSQL en tu proyecto Spring Boot.
