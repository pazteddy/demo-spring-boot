# API de Gestión de Órdenes

## Descripción
Esta API permite a los usuarios autenticados crear y gestionar órdenes de compra con múltiples productos.

## Endpoints Disponibles

### 1. Crear Orden
**POST** `/api/ordenes`

Crea una nueva orden para el usuario autenticado.

**Headers requeridos:**
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Request Body:**
```json
{
  "detalles": [
    {
      "productoId": 1,
      "cantidad": 2
    },
    {
      "productoId": 3,
      "cantidad": 1
    }
  ]
}
```

**Response (201 Created):**
```json
{
  "id": 1,
  "usuarioId": 123,
  "usuarioNombre": "usuario123",
  "fecha": "2025-01-13T10:30:00",
  "total": 45.99,
  "detalles": [
    {
      "id": 1,
      "productoId": 1,
      "productoNombre": "Producto A",
      "cantidad": 2,
      "precioUnitario": 15.50,
      "subtotal": 31.00
    },
    {
      "id": 2,
      "productoId": 3,
      "productoNombre": "Producto C",
      "cantidad": 1,
      "precioUnitario": 14.99,
      "subtotal": 14.99
    }
  ]
}
```

### 2. Listar Órdenes del Usuario
**GET** `/api/ordenes`

Obtiene todas las órdenes del usuario autenticado.

**Headers requeridos:**
```
Authorization: Bearer <jwt_token>
```

**Response (200 OK):**
```json
[
  {
    "id": 1,
    "fecha": "2025-01-13T10:30:00",
    "total": 45.99,
    "cantidadItems": 2
  },
  {
    "id": 2,
    "fecha": "2025-01-12T15:20:00",
    "total": 29.99,
    "cantidadItems": 1
  }
]
```

### 3. Obtener Detalle de Orden
**GET** `/api/ordenes/{id}`

Obtiene el detalle completo de una orden específica.

**Headers requeridos:**
```
Authorization: Bearer <jwt_token>
```

**Path Parameters:**
- `id`: ID de la orden a consultar

**Response (200 OK):**
```json
{
  "id": 1,
  "usuarioId": 123,
  "usuarioNombre": "usuario123",
  "fecha": "2025-01-13T10:30:00",
  "total": 45.99,
  "detalles": [
    {
      "id": 1,
      "productoId": 1,
      "productoNombre": "Producto A",
      "cantidad": 2,
      "precioUnitario": 15.50,
      "subtotal": 31.00
    }
  ]
}
```

### 4. Verificar Existencia de Orden
**GET** `/api/ordenes/{id}/exists`

Verifica si una orden existe y pertenece al usuario autenticado.

**Headers requeridos:**
```
Authorization: Bearer <jwt_token>
```

**Response (200 OK):**
```json
true
```

## Códigos de Error

### 400 Bad Request
- `INSUFFICIENT_STOCK`: Stock insuficiente para completar la orden
- `EMPTY_ORDER`: La orden debe tener al menos un producto

### 401 Unauthorized
- Token JWT inválido o faltante

### 403 Forbidden
- `ACCESS_DENIED`: Intento de acceder a una orden que no pertenece al usuario

### 404 Not Found
- `ORDEN_NOT_FOUND`: Orden no encontrada
- `PRODUCT_NOT_FOUND`: Producto no encontrado

### 500 Internal Server Error
- Error interno del servidor

## Validaciones

### Crear Orden
- La orden debe tener al menos un detalle
- Cada detalle debe tener un `productoId` válido
- La `cantidad` debe ser mayor a 0
- El producto debe existir en la base de datos
- Debe haber stock suficiente para cada producto

### Seguridad
- Solo el usuario autenticado puede crear órdenes
- Solo el usuario puede ver sus propias órdenes
- No se puede acceder a órdenes de otros usuarios

## Flujo de Negocio

1. **Crear Orden:**
   - Se valida que el usuario esté autenticado
   - Se verifica la existencia de todos los productos
   - Se valida que hay stock suficiente
   - Se crea la orden y sus detalles
   - Se actualiza el stock de los productos
   - Se retorna la orden completa

2. **Consultar Órdenes:**
   - Se filtran automáticamente por el usuario autenticado
   - Se incluyen los detalles con información de productos
   - Se calculan los totales dinámicamente

## Pasos para Probar la API

### 1. Autenticarse primero
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "tu_usuario", "password": "tu_password"}'
```

### 2. Crear una orden (usando el token de la respuesta anterior)
```bash
curl -X POST http://localhost:8080/api/ordenes \
  -H "Authorization: Bearer TU_JWT_TOKEN_AQUI" \
  -H "Content-Type: application/json" \
  -d '{
    "detalles": [
      {"productoId": 1, "cantidad": 2},
      {"productoId": 2, "cantidad": 1}
    ]
  }'
```

### 3. Listar órdenes del usuario
```bash
curl -X GET http://localhost:8080/api/ordenes \
  -H "Authorization: Bearer TU_JWT_TOKEN_AQUI"
```

### 4. Obtener detalle de una orden
```bash
curl -X GET http://localhost:8080/api/ordenes/1 \
  -H "Authorization: Bearer TU_JWT_TOKEN_AQUI"
```

## Nota Importante
Asegúrate de:
1. Tener productos creados en la base de datos con stock suficiente
2. Usar un token JWT válido obtenido del endpoint de login
3. Que las tablas `ordenes` y `ordenes_detalles` estén creadas en la base de datos
