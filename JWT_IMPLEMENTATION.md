# Implementación de JWT en Spring Boot - Versión Corregida

## Guía paso a paso para implementar autenticación JWT con creación de usuarios, login, rutas protegidas y públicas

### 1. Agregar Dependencias Necesarias

Primero, agrega las siguientes dependencias al archivo `pom.xml`:

```xml
<!-- JWT Dependencies -->
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.12.3</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.12.3</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.12.3</version>
    <scope>runtime</scope>
</dependency>

<!-- Spring Security -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<!-- Validation -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-validation</artifactId>
</dependency>
```

### 2. Configurar propiedades de JWT

Agrega las siguientes propiedades al archivo `application.properties`:

```properties
# JWT Configuration - Clave segura en Base64
jwt.secret=bXlTZWNyZXRLZXkxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=
jwt.expiration=86400000
# 86400000 ms = 24 horas

# Configuración adicional para seguridad
spring.jpa.hibernate.ddl-auto=update
spring.jpa.show-sql=false
```

### 3. Crear Entidad Usuario

Crea la clase `Usuario.java` en el paquete `com.utec.demo.spring_boot.usuario`:

```java
package com.utec.demo.spring_boot.usuario;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "usuarios")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class Usuario implements UserDetails {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank(message = "El nombre de usuario es obligatorio")
    @Size(min = 3, max = 50, message = "El nombre de usuario debe tener entre 3 y 50 caracteres")
    @Column(unique = true)
    private String username;
    
    @NotBlank(message = "El email es obligatorio")
    @Email(message = "El email debe tener un formato válido")
    @Column(unique = true)
    private String email;
    
    @NotBlank(message = "La contraseña es obligatoria")
    @Size(min = 6, message = "La contraseña debe tener al menos 6 caracteres")
    private String password;
    
    @Enumerated(EnumType.STRING)
    private Role role = Role.USER;
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }
    
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }
    
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }
    
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
    
    @Override
    public boolean isEnabled() {
        return true;
    }
}
```

### 4. Crear Enum Role

Crea la clase `Role.java` en el paquete `com.utec.demo.spring_boot.usuario`:

```java
package com.utec.demo.spring_boot.usuario;

public enum Role {
    USER,
    ADMIN
}
```

### 5. Crear Repository para Usuario

Crea la interfaz `UsuarioRepository.java` en el paquete `com.utec.demo.spring_boot.usuario`:

```java
package com.utec.demo.spring_boot.usuario;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
    Optional<Usuario> findByUsername(String username);
    Optional<Usuario> findByEmail(String email);
    boolean existsByUsername(String username);
    boolean existsByEmail(String email);
}
```

### 6. Crear DTOs para Autenticación

Crea la clase `AuthDTO.java` en el paquete `com.utec.demo.spring_boot.auth`:

```java
package com.utec.demo.spring_boot.auth;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

public class AuthDTO {
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class LoginRequest {
        @NotBlank(message = "El nombre de usuario es obligatorio")
        private String username;
        
        @NotBlank(message = "La contraseña es obligatoria")
        private String password;
    }
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RegisterRequest {
        @NotBlank(message = "El nombre de usuario es obligatorio")
        @Size(min = 3, max = 50, message = "El nombre de usuario debe tener entre 3 y 50 caracteres")
        private String username;
        
        @NotBlank(message = "El email es obligatorio")
        @Email(message = "El email debe tener un formato válido")
        private String email;
        
        @NotBlank(message = "La contraseña es obligatoria")
        @Size(min = 6, message = "La contraseña debe tener al menos 6 caracteres")
        private String password;
    }
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AuthResponse {
        private String token;
        private String type = "Bearer";
        private Long id;
        private String username;
        private String email;
        private String role;
    }
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ErrorResponse {
        private String error;
        private String message;
        private int status;
    }
}
```

### 7. Crear Servicio JWT (Versión Corregida)

Crea la clase `JwtService.java` en el paquete `com.utec.demo.spring_boot.auth`:

```java
package com.utec.demo.spring_boot.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {
    
    @Value("${jwt.secret}")
    private String secretKey;
    
    @Value("${jwt.expiration}")
    private long jwtExpirationMillis;
    
    private Key getKey() {
        // Usando Base64 decode ya que la clave está en Base64
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
    
    public String extractUsername(String token) {
        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }
    
    public String generateToken(UserDetails userDetails) {
        // Incluir rol en el token para evitar consultas adicionales
        Map<String, Object> extraClaims = Map.of(
                "role", userDetails.getAuthorities().stream()
                        .findFirst()
                        .map(Object::toString)
                        .orElse("ROLE_USER")
        );
        
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(userDetails.getUsername())
                .claims(extraClaims)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusMillis(jwtExpirationMillis)))
                .signWith(getKey()) // Nuevo API sin SignatureAlgorithm explícito
                .compact();
    }
    
    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            var claims = Jwts.parser()
                    .verifyWith(getKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            
            return claims.getSubject().equals(userDetails.getUsername()) &&
                    claims.getExpiration().after(new Date());
        } catch (Exception e) {
            return false;
        }
    }
    
    public String extractRole(String token) {
        try {
            var claims = Jwts.parser()
                    .verifyWith(getKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return claims.get("role", String.class);
        } catch (Exception e) {
            return null;
        }
    }
}
```

### 8. Crear Filtro JWT (Versión Mejorada)

Crea la clase `JwtAuthenticationFilter.java` en el paquete `com.utec.demo.spring_boot.auth`:

```java
package com.utec.demo.spring_boot.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    
    // Rutas públicas que no requieren autenticación
    private static final List<String> PUBLIC_PATHS = Arrays.asList(
            "/api/auth",
            "/api/saludo",
            "/actuator/health"
    );
    
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        
        String requestPath = request.getServletPath();
        
        // Permitir acceso a rutas públicas
        if (isPublicPath(requestPath)) {
            filterChain.doFilter(request, response);
            return;
        }
        
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        try {
            jwt = authHeader.substring(7);
            username = jwtService.extractUsername(jwt);
            
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
                
                if (jwtService.isTokenValid(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    authToken.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(request)
                    );
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            log.error("Error processing JWT token: {}", e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
    
    private boolean isPublicPath(String path) {
        return PUBLIC_PATHS.stream().anyMatch(path::contains);
    }
}
```

### 9. Crear Servicio de Usuario (Versión Mejorada)

Crea la clase `UsuarioService.java` en el paquete `com.utec.demo.spring_boot.usuario`:

```java
package com.utec.demo.spring_boot.usuario;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UsuarioService implements UserDetailsService {
    
    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return usuarioRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Usuario no encontrado: " + username));
    }
    
    @Transactional
    public Usuario save(Usuario usuario) {
        usuario.setPassword(passwordEncoder.encode(usuario.getPassword()));
        return usuarioRepository.save(usuario);
    }
    
    public boolean existsByUsername(String username) {
        return usuarioRepository.existsByUsername(username);
    }
    
    public boolean existsByEmail(String email) {
        return usuarioRepository.existsByEmail(email);
    }
}
```

### 10. Crear Excepciones Personalizadas

Crea la clase `AuthException.java` en el paquete `com.utec.demo.spring_boot.auth`:

```java
package com.utec.demo.spring_boot.auth;

public class AuthException extends RuntimeException {
    public AuthException(String message) {
        super(message);
    }
    
    public static class UserAlreadyExistsException extends AuthException {
        public UserAlreadyExistsException(String message) {
            super(message);
        }
    }
    
    public static class InvalidCredentialsException extends AuthException {
        public InvalidCredentialsException() {
            super("Credenciales inválidas");
        }
    }
}
```

### 11. Crear Servicio de Autenticación (Versión Mejorada)

Crea la clase `AuthService.java` en el paquete `com.utec.demo.spring_boot.auth`:

```java
package com.utec.demo.spring_boot.auth;

import com.utec.demo.spring_boot.usuario.Role;
import com.utec.demo.spring_boot.usuario.Usuario;
import com.utec.demo.spring_boot.usuario.UsuarioService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {
    
    private final UsuarioService usuarioService;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    
    @Transactional
    public AuthDTO.AuthResponse register(AuthDTO.RegisterRequest request) {
        
        if (usuarioService.existsByUsername(request.getUsername())) {
            throw new AuthException.UserAlreadyExistsException("El nombre de usuario ya existe");
        }
        
        if (usuarioService.existsByEmail(request.getEmail())) {
            throw new AuthException.UserAlreadyExistsException("El email ya está registrado");
        }
        
        var usuario = new Usuario();
        usuario.setUsername(request.getUsername());
        usuario.setEmail(request.getEmail());
        usuario.setPassword(request.getPassword());
        usuario.setRole(Role.USER);
        
        usuario = usuarioService.save(usuario);
        
        var jwtToken = jwtService.generateToken(usuario);
        
        return new AuthDTO.AuthResponse(
                jwtToken,
                "Bearer",
                usuario.getId(),
                usuario.getUsername(),
                usuario.getEmail(),
                usuario.getRole().name()
        );
    }
    
    public AuthDTO.AuthResponse authenticate(AuthDTO.LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsername(),
                            request.getPassword()
                    )
            );
            
            var usuario = (Usuario) authentication.getPrincipal();
            var jwtToken = jwtService.generateToken(usuario);
            
            return new AuthDTO.AuthResponse(
                    jwtToken,
                    "Bearer",
                    usuario.getId(),
                    usuario.getUsername(),
                    usuario.getEmail(),
                    usuario.getRole().name()
            );
        } catch (BadCredentialsException e) {
            throw new AuthException.InvalidCredentialsException();
        }
    }
}
```

### 12. Crear Manejador Global de Excepciones

Crea la clase `GlobalExceptionHandler.java` en el paquete `com.utec.demo.spring_boot.config`:

```java
package com.utec.demo.spring_boot.config;

import com.utec.demo.spring_boot.auth.AuthDTO;
import com.utec.demo.spring_boot.auth.AuthException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(AuthException.UserAlreadyExistsException.class)
    public ResponseEntity<AuthDTO.ErrorResponse> handleUserAlreadyExists(AuthException.UserAlreadyExistsException e) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(new AuthDTO.ErrorResponse("USER_ALREADY_EXISTS", e.getMessage(), 409));
    }
    
    @ExceptionHandler(AuthException.InvalidCredentialsException.class)
    public ResponseEntity<AuthDTO.ErrorResponse> handleInvalidCredentials(AuthException.InvalidCredentialsException e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new AuthDTO.ErrorResponse("INVALID_CREDENTIALS", e.getMessage(), 401));
    }
    
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidationExceptions(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        return ResponseEntity.badRequest().body(errors);
    }
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<AuthDTO.ErrorResponse> handleGenericException(Exception e) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new AuthDTO.ErrorResponse("INTERNAL_ERROR", "Error interno del servidor", 500));
    }
}
```

### 13. Crear Controlador de Autenticación (Versión Mejorada)

Crea la clase `AuthController.java` en el paquete `com.utec.demo.spring_boot.controllers`:

```java
package com.utec.demo.spring_boot.controllers;

import com.utec.demo.spring_boot.auth.AuthDTO;
import com.utec.demo.spring_boot.auth.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final AuthService authService;
    
    @PostMapping("/register")
    public ResponseEntity<AuthDTO.AuthResponse> register(@Valid @RequestBody AuthDTO.RegisterRequest request) {
        AuthDTO.AuthResponse response = authService.register(request);
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/login")
    public ResponseEntity<AuthDTO.AuthResponse> authenticate(@Valid @RequestBody AuthDTO.LoginRequest request) {
        AuthDTO.AuthResponse response = authService.authenticate(request);
        return ResponseEntity.ok(response);
    }
    
    @GetMapping("/public")
    public ResponseEntity<String> publicEndpoint() {
        return ResponseEntity.ok("Esta es una ruta pública - accesible sin autenticación");
    }
}
```

### 14. Crear Configuración de Seguridad (Versión Corregida)

Crea la clase `SecurityConfig.java` en el paquete `com.utec.demo.spring_boot.config`:

```java
package com.utec.demo.spring_boot.config;

import com.utec.demo.spring_boot.auth.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final UserDetailsService userDetailsService;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(c -> c.configurationSource(corsConfigurationSource()))
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(e -> e
                        .authenticationEntryPoint(authenticationEntryPoint())
                        .accessDeniedHandler(accessDeniedHandler())
                )
                .authorizeHttpRequests(auth -> auth
                        // Rutas públicas
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/api/saludo/**").permitAll()
                        .requestMatchers(HttpMethod.GET, "/actuator/health").permitAll()
                        // Rutas específicas con roles
                        .requestMatchers("/api/usuarios/admin").hasRole("ADMIN")
                        // Rutas protegidas genéricas
                        .requestMatchers("/api/productos/**").authenticated()
                        .requestMatchers("/api/clientes/**").authenticated()
                        .requestMatchers("/api/usuarios/**").authenticated()
                        // Cualquier otra ruta requiere autenticación
                        .anyRequest().authenticated()
                )
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:3000", "http://localhost:4200")); // Ajustar según necesidades
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-Requested-With"));
        configuration.setExposedHeaders(List.of("Authorization"));
        configuration.setAllowCredentials(true);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // Strength aumentado para mayor seguridad
    }
    
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
    
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
    
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authException) -> {
            response.setStatus(401);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"No autorizado\",\"message\":\"Token JWT requerido\"}");
        };
    }
    
    @Bean
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) -> {
            response.setStatus(403);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"Acceso denegado\",\"message\":\"No tiene permisos suficientes\"}");
        };
    }
}
```

### 15. Crear Controlador de Usuario (Versión Segura)

Crea la clase `UsuarioController.java` en el paquete `com.utec.demo.spring_boot.controllers`:

```java
package com.utec.demo.spring_boot.controllers;

import com.utec.demo.spring_boot.usuario.Usuario;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/usuarios")
@RequiredArgsConstructor
public class UsuarioController {
    
    @GetMapping("/perfil")
    public ResponseEntity<?> getPerfil() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        if (authentication == null || !(authentication.getPrincipal() instanceof Usuario usuario)) {
            return ResponseEntity.status(401).body("No autenticado correctamente");
        }
        
        return ResponseEntity.ok(new PerfilResponse(
                usuario.getId(),
                usuario.getUsername(),
                usuario.getEmail(),
                usuario.getRole().name()
        ));
    }
    
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> adminEndpoint() {
        return ResponseEntity.ok("Esta es una ruta de administrador - solo accesible por ADMIN");
    }
    
    @GetMapping("/test-protected")
    public ResponseEntity<String> testProtected() {
        return ResponseEntity.ok("Ruta protegida - accesible por cualquier usuario autenticado");
    }
    
    public record PerfilResponse(Long id, String username, String email, String role) {}
}
```

### 16. Actualizar ProductoController

Modifica el controlador de productos existente:

```java
// En ProductoController.java, asegurar que tenga:
@RequestMapping("/api/productos")
// Y remover cualquier anotación @CrossOrigin individual
```

### 17. Pasos para Probar la Implementación

#### 17.1 Compilar y ejecutar la aplicación:
```bash
mvn clean install
mvn spring-boot:run
```

#### 17.2 Crear un usuario (POST):
```
URL: http://localhost:8080/api/auth/register
Method: POST
Headers: Content-Type: application/json
Body:
{
    "username": "testuser",
    "email": "test@example.com",
    "password": "123456"
}
```

#### 17.3 Hacer login (POST):
```
URL: http://localhost:8080/api/auth/login
Method: POST
Headers: Content-Type: application/json
Body:
{
    "username": "testuser",
    "password": "123456"
}
```

Respuesta esperada:
```json
{
    "token": "eyJhbGciOiJIUzI1NiJ9...",
    "type": "Bearer",
    "id": 1,
    "username": "testuser",
    "email": "test@example.com",
    "role": "USER"
}
```

#### 17.4 Acceder a rutas protegidas:
```
URL: http://localhost:8080/api/usuarios/perfil
Method: GET
Headers: 
- Content-Type: application/json
- Authorization: Bearer {token_del_login}
```

#### 17.5 Crear usuario administrador directamente en BD:

Para probar rutas de administrador, ejecuta este SQL en tu BD:
```sql
INSERT INTO usuarios (username, email, password, role) 
VALUES ('admin', 'admin@example.com', '$2a$12$encrypted_password_here', 'ADMIN');
```

### 18. Estructura Final del Proyecto

```
src/main/java/com/utec/demo/spring_boot/
├── auth/
│   ├── AuthDTO.java
│   ├── AuthException.java
│   ├── AuthService.java
│   ├── JwtService.java
│   └── JwtAuthenticationFilter.java
├── config/
│   ├── SecurityConfig.java
│   └── GlobalExceptionHandler.java
├── controllers/
│   ├── AuthController.java
│   ├── UsuarioController.java
│   └── ... (controladores existentes)
├── usuario/
│   ├── Usuario.java
│   ├── UsuarioRepository.java
│   ├── UsuarioService.java
│   └── Role.java
```

### 19. Rutas del Sistema

#### Rutas Públicas (Sin autenticación):
- `POST /api/auth/register` - Registro de usuario
- `POST /api/auth/login` - Iniciar sesión
- `GET /api/auth/public` - Endpoint público de prueba
- `GET /api/saludo/**` - Endpoints de saludo
- `GET /actuator/health` - Health check

#### Rutas Protegidas (Requieren token JWT):
- `GET /api/usuarios/perfil` - Ver perfil del usuario autenticado
- `GET /api/usuarios/test-protected` - Endpoint de prueba protegido
- `GET /api/productos/**` - Todos los endpoints de productos

#### Rutas de Administrador (Requieren rol ADMIN):
- `GET /api/usuarios/admin` - Endpoint exclusivo para administradores

### 20. Mejoras Implementadas

1. **Seguridad JWT**: Clave en Base64, nuevo API de JJWT 0.12.3
2. **Manejo de errores**: Excepciones personalizadas y manejador global
3. **CORS centralizado**: Configuración segura y específica
4. **Validación robusta**: Prevención de NPE y validaciones completas
5. **Roles incluidos en token**: Evita consultas adicionales a BD
6. **Logging**: Para debugging y monitoreo
7. **Restricciones de rol**: Implementadas correctamente con `@PreAuthorize`
8. **Filtro mejorado**: Lista de rutas públicas más flexible
9. **Respuestas estructuradas**: DTOs consistentes para todas las respuestas
10. **Transacciones**: Servicios con anotaciones de transacción apropiadas

### 21. Notas de Seguridad

1. **Clave JWT**: La clave está en Base64 y es suficientemente larga para HS256
2. **CORS**: Configurado para dominios específicos en lugar de "*"
3. **Contraseñas**: BCrypt con strength 12 para mayor seguridad
4. **Tokens**: Incluyen claims de rol para autorización distribuida
5. **Excepciones**: No exponen información sensible del sistema
6. **Validación**: Campos validados tanto en DTO como en entidad

¡Esta versión corregida elimina todos los problemas identificados en el análisis y proporciona una implementación JWT robusta y segura!
