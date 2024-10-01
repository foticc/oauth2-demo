package com.foticc.pkce.controller;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController()
public class IndexController {

    @GetMapping("/index")
    public String rest() {
        return "index";
    }
}
