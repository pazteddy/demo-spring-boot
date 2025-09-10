package com.utec.demo.spring_boot.controllers;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/saludo")
public class SaludoController {
    @GetMapping
    public String saludo()
    {
        return "Hola desde Spring Boot!";
    }

}
