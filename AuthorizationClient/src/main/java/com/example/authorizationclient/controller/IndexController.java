package com.example.authorizationclient.controller;

import org.springframework.security.authentication.jaas.JaasAuthenticationToken;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;

@RestController
public class IndexController {


    @GetMapping("/token")
    public OAuth2AuthorizedClient token(@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient oAuth2AuthorizedClient) {
        return oAuth2AuthorizedClient;
    }

    @GetMapping("/test")
    public String test() {
        return "test";
    }

}
