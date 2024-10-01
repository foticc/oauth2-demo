package com.example.authorizationresource.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @GetMapping("/message")
    public String message() {
        return "hello message";
    }

    @GetMapping("/message2")
    @PreAuthorize("hasAuthority('SCOPE_profile')")
    public String message2() {
        return "message2";
    }

    @GetMapping("/message3")
    @PreAuthorize("hasAuthority('SCOPE_message')")
    public String message3() {
        return "message3";
    }


}
