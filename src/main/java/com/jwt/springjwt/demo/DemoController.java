package com.jwt.springjwt.demo;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo-controller")
public class DemoController {

    @GetMapping
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("Hello from secured endpoint");
    }
    @RolesAllowed("ADMIN")
    @GetMapping("/abdo")
    public ResponseEntity<String> sayAbdo() {
        return ResponseEntity.ok("Hello Abdo");
    }

}