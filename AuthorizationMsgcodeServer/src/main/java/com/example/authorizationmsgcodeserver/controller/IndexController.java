package com.example.authorizationmsgcodeserver.controller;

import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
public class IndexController {
    private final JavaMailSender javaMailSender;

    public IndexController(JavaMailSender javaMailSender) {
        this.javaMailSender = javaMailSender;
    }

    @GetMapping("/send")
    public String code() {
        SimpleMailMessage simpleMailMessage = new SimpleMailMessage();
        simpleMailMessage.setText(UUID.randomUUID().toString());
        javaMailSender.send(simpleMailMessage);
        return "hello";
    }
}
