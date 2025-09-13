-- Scripts SQL para crear las tablas de órdenes y detalles de órdenes

-- Tabla ordenes
CREATE TABLE IF NOT EXISTS ordenes (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    fecha TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_ordenes_usuario FOREIGN KEY (user_id)
        REFERENCES usuarios(id) ON DELETE RESTRICT
);

-- Índices para mejorar el rendimiento
CREATE INDEX IF NOT EXISTS idx_ordenes_user_id ON ordenes(user_id);
CREATE INDEX IF NOT EXISTS idx_ordenes_fecha ON ordenes(fecha DESC);

-- Tabla ordenes_detalles
CREATE TABLE IF NOT EXISTS ordenes_detalles (
    id BIGSERIAL PRIMARY KEY,
    orden_id BIGINT NOT NULL,
    producto_id BIGINT NOT NULL,
    cantidad INTEGER NOT NULL CHECK (cantidad > 0),
    precio_unitario DECIMAL(10,2) NOT NULL CHECK (precio_unitario > 0),
    CONSTRAINT fk_ordenes_detalles_orden FOREIGN KEY (orden_id)
        REFERENCES ordenes(id) ON DELETE CASCADE,
    CONSTRAINT fk_ordenes_detalles_producto FOREIGN KEY (producto_id)
        REFERENCES productos(id) ON DELETE RESTRICT
);

-- Índices para mejorar el rendimiento
CREATE INDEX IF NOT EXISTS idx_ordenes_detalles_orden_id ON ordenes_detalles(orden_id);
CREATE INDEX IF NOT EXISTS idx_ordenes_detalles_producto_id ON ordenes_detalles(producto_id);

-- Comentarios para documentar las tablas
COMMENT ON TABLE ordenes IS 'Tabla que almacena las órdenes de compra de los usuarios';
COMMENT ON COLUMN ordenes.id IS 'Identificador único de la orden';
COMMENT ON COLUMN ordenes.user_id IS 'ID del usuario que realizó la orden';
COMMENT ON COLUMN ordenes.fecha IS 'Fecha y hora de creación de la orden';

COMMENT ON TABLE ordenes_detalles IS 'Tabla que almacena los detalles/items de cada orden';
COMMENT ON COLUMN ordenes_detalles.id IS 'Identificador único del detalle';
COMMENT ON COLUMN ordenes_detalles.orden_id IS 'ID de la orden a la que pertenece este detalle';
COMMENT ON COLUMN ordenes_detalles.producto_id IS 'ID del producto en este detalle';
COMMENT ON COLUMN ordenes_detalles.cantidad IS 'Cantidad del producto ordenada';
COMMENT ON COLUMN ordenes_detalles.precio_unitario IS 'Precio unitario del producto al momento de la orden';
