# Demo Spring Boot

![Java](https://img.shields.io/badge/Java-17+-blue?logo=java)
![Spring Boot](https://img.shields.io/badge/Spring_Boot-3.x-brightgreen?logo=springboot)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Database-informational?logo=postgresql)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

Este proyecto es una aplicación de ejemplo construida con **Spring Boot**.  
Incluye implementaciones de autenticación con JWT, persistencia con JPA y PostgreSQL, y ejemplos de APIs REST documentadas.

---

## 🚀 Tecnologías utilizadas
- Java 17+
- Spring Boot
- Spring Data JPA
- PostgreSQL
- Maven
- JWT (JSON Web Tokens)
- Spring REST Docs

---

## 📂 Estructura del proyecto
- `src/main/java` → Código fuente principal (controladores, servicios, repositorios, entidades).
- `src/main/resources` → Archivos de configuración (application.properties, scripts, etc.).
- `pom.xml` → Archivo de dependencias Maven.
- Documentación adicional:
  - `README_CLIENTES.md` → Guía sobre clientes.
  - `README_JPA_POSTGRESQL.md` → Persistencia con JPA y PostgreSQL.
  - `README_ORDENES_API.md` → Documentación de la API de órdenes.
  - `JWT_IMPLEMENTATION.md` → Implementación de JWT.
  - `SPRING_REST_DOCS.md` → Integración de Spring REST Docs.

---

## ⚙️ Requisitos previos
- JDK 17 o superior instalado
- Maven 3.8+
- PostgreSQL en ejecución

---

## ▶️ Ejecución
1. Clonar el repositorio:
   ```bash
   git clone https://github.com/pazteddy/demo-spring-boot.git
   cd demo-spring-boot
   ```
2. Configurar la base de datos en `application.properties`.
3. Compilar y ejecutar:
   ```bash
   mvn spring-boot:run
   ```

---

## 📖 Endpoints principales
La aplicación expone endpoints REST (clientes, órdenes, autenticación).  
Puedes encontrar detalles en la documentación incluida en el repositorio.

Ejemplo de autenticación:
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

---

## 📜 Licencia
Este proyecto está bajo la licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.

---

## 🧑‍💻 Autor
Desarrollado por [Teddy Paz](https://github.com/pazteddy).
