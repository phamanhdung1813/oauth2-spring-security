package com.anhdungpham.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    @GetMapping(value = "/test1")
    public String test() {
        return "TEST 1!!!";
    }

    @GetMapping(value = "/test2")
    public String test2() {
        return "TEST 2 !!!";
    }
}
