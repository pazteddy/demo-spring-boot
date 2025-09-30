package com.utec.demo.spring_boot.producto;

public class ProductoDTO {
    private String title;
    private String imgSrc;
    private Double price;
    private Integer stock;

    public ProductoDTO() {
    }

    public ProductoDTO(String title, String imgSrc, Double price, Integer stock) {
        this.title = title;
        this.imgSrc = imgSrc;
        this.price = price;
        this.stock = stock;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getImgSrc() {
        return imgSrc;
    }

    public void setImgSrc(String imgSrc) {
        this.imgSrc = imgSrc;
    }

    public Double getPrice() {
        return price;
    }

    public void setPrice(Double price) {
        this.price = price;
    }

    public Integer getStock() {
        return stock;
    }

    public void setStock(Integer stock) {
        this.stock = stock;
    }
}
