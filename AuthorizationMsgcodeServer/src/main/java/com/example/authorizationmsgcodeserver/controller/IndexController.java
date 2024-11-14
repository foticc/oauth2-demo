package com.example.authorizationmsgcodeserver.controller;

import com.example.authorizationmsgcodeserver.config.VirtualMessageContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @GetMapping("/send")
    public String code(@RequestParam String username) {
        return VirtualMessageContext.getInstance().message(username);
    }
}
