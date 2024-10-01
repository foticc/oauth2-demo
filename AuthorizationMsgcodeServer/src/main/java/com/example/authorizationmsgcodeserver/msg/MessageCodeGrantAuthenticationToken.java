package com.example.authorizationmsgcodeserver.msg;

import com.example.authorizationmsgcodeserver.config.OAuth2Constant;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;

public class MessageCodeGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    /**
     * Sub-class constructor.
     * @param clientPrincipal        the authenticated client principal
     * @param additionalParameters   the additional parameters
     */
    protected MessageCodeGrantAuthenticationToken(Authentication clientPrincipal, Map<String, Object> additionalParameters) {
        super(new AuthorizationGrantType(OAuth2Constant.GRANT_TYPE_MESSAGE_CODE), clientPrincipal, additionalParameters);
    }
}
