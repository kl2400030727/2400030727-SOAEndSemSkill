package com.example.driverservice.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RiderController {

    @Autowired
    private Environment environment;

    @GetMapping("/rider")
    public String getRider() {

        String port = environment.getProperty("local.server.port");

        return "Rider Controller is running on DriverService Port: " + port;
    }
}