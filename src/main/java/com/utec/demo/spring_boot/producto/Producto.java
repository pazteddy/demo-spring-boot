package com.utec.demo.spring_boot.producto;

public class Producto {
    private Long id;
    private String nombre;
    private Double precio;
    public Producto(Long id,String nombre,Double precio){
        this.id = id;
        this.nombre = nombre;
        this.precio = precio;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public Double getPrecio() {
        return precio;
    }

    public void setPrecio(Double precio) {
        this.precio = precio;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }
}
