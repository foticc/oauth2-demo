package com.foticc.pkce.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

public class FormAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String error = UriComponentsBuilder.fromPath("/auth/page")
                .queryParam("error", exception.getMessage())
                .build().encode().toUriString();
        response.sendRedirect(error);
    }
}
