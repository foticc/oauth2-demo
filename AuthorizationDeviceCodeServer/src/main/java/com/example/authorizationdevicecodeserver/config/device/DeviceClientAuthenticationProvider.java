package com.example.authorizationdevicecodeserver.config.device;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

public class DeviceClientAuthenticationProvider implements AuthenticationProvider {
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1";

    private static final Logger logger = LoggerFactory.getLogger(DeviceClientAuthenticationProvider.class);


    private final RegisteredClientRepository registeredClientRepository;

    public DeviceClientAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.registeredClientRepository = registeredClientRepository;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        DeviceClientAuthenticationToken deviceClientAuthentication =
                (DeviceClientAuthenticationToken) authentication;
        if (!ClientAuthenticationMethod.NONE.equals(deviceClientAuthentication.getClientAuthenticationMethod())) {
            return null;
        }
        String clientId = deviceClientAuthentication.getPrincipal().toString();
        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);

        if (registeredClient == null) {
            throwInvalidClient(OAuth2ParameterNames.CLIENT_ID);
        }

        if (logger.isTraceEnabled()) {
            logger.trace("Retrieved registered client");
        }

        if (!registeredClient.getClientAuthenticationMethods().contains(
                deviceClientAuthentication.getClientAuthenticationMethod())) {
            throwInvalidClient("authentication_method");
        }

        if (logger.isTraceEnabled()) {
            logger.trace("Validated device client authentication parameters");
        }

        if (logger.isTraceEnabled()) {
            logger.trace("Authenticated device client");
        }

        return new DeviceClientAuthenticationToken(registeredClient,
                deviceClientAuthentication.getClientAuthenticationMethod(), null);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return DeviceClientAuthenticationToken.class.isAssignableFrom(authentication);
    }


    private static void throwInvalidClient(String parameterName) {
        OAuth2Error error = new OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "Device client authentication failed: " + parameterName,
                ERROR_URI
        );
        throw new OAuth2AuthenticationException(error);
    }
}
