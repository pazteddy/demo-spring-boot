# Guía paso a paso: Implementar la entidad Cliente con JPA, Hibernate y PostgreSQL en Spring Boot

Este documento te guiará para crear la entidad `Cliente` y su CRUD completo en tu proyecto Spring Boot, utilizando JPA/Hibernate y PostgreSQL.

---

## 1. Crear la entidad `Cliente`

Crea el archivo `Cliente.java` en el paquete `producto` o en un nuevo paquete `cliente` si prefieres separar las entidades:

```java
package com.utec.demo.spring_boot.producto;

import jakarta.persistence.*;

@Entity
@Table(name = "clientes")
public class Cliente {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String nombre;
    private String email;
    private String direccion;

    // Getters y setters
}
```

---

## 2. Crear el repositorio JPA

Crea la interfaz `ClienteRepository.java` en el mismo paquete:

```java
package com.utec.demo.spring_boot.producto;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ClienteRepository extends JpaRepository<Cliente, Long> {
}
```

---

## 3. Crear el servicio para clientes

Crea el archivo `ClienteService.java`:

```java
package com.utec.demo.spring_boot.producto;

import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;

@Service
public class ClienteService {
    private final ClienteRepository clienteRepository;

    public ClienteService(ClienteRepository clienteRepository) {
        this.clienteRepository = clienteRepository;
    }

    public List<Cliente> listarTodos() {
        return clienteRepository.findAll();
    }

    public Optional<Cliente> obtenerPorId(Long id) {
        return clienteRepository.findById(id);
    }

    public Cliente guardar(Cliente cliente) {
        return clienteRepository.save(cliente);
    }

    public void eliminar(Long id) {
        clienteRepository.deleteById(id);
    }
}
```

---

## 4. Crear el controlador REST

Crea el archivo `ClienteController.java` en el paquete `controllers`:

```java
package com.utec.demo.spring_boot.controllers;

import com.utec.demo.spring_boot.producto.Cliente;
import com.utec.demo.spring_boot.producto.ClienteService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/clientes")
public class ClienteController {
    private final ClienteService clienteService;

    public ClienteController(ClienteService clienteService) {
        this.clienteService = clienteService;
    }

    @GetMapping
    public List<Cliente> listar() {
        return clienteService.listarTodos();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Cliente> obtener(@PathVariable Long id) {
        return clienteService.obtenerPorId(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public Cliente crear(@RequestBody Cliente cliente) {
        return clienteService.guardar(cliente);
    }

    @PutMapping("/{id}")
    public ResponseEntity<Cliente> actualizar(@PathVariable Long id, @RequestBody Cliente cliente) {
        return clienteService.obtenerPorId(id)
                .map(c -> {
                    cliente.setId(id);
                    return ResponseEntity.ok(clienteService.guardar(cliente));
                })
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> eliminar(@PathVariable Long id) {
        if (clienteService.obtenerPorId(id).isPresent()) {
            clienteService.eliminar(id);
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.notFound().build();
    }
}
```

---

## 5. Crear la tabla en PostgreSQL

Puedes dejar que Hibernate la cree automáticamente (`ddl-auto=update`) o crearla manualmente:

```sql
CREATE TABLE clientes (
    id SERIAL PRIMARY KEY,
    nombre VARCHAR(255),
    email VARCHAR(255),
    direccion VARCHAR(255)
);
```

---

## 6. Probar el CRUD

- Levanta tu aplicación: `./mvnw spring-boot:run`
- Usa Postman, curl o similar para probar los endpoints:
    - `GET /api/clientes`
    - `GET /api/clientes/{id}`
    - `POST /api/clientes`
    - `PUT /api/clientes/{id}`
    - `DELETE /api/clientes/{id}`

---

¡Listo! Ahora tienes un CRUD completo para la entidad Cliente en tu proyecto Spring Boot.

