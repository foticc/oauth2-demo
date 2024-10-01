package com.example.authorizationpasswordserver.password;

import com.example.authorizationpasswordserver.config.OAuth2Constant;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;

import java.util.Map;

/***
 * 自定义密码模式 的 token
 */
public class PasswordGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken  {

    /**
     * Sub-class constructor.
     *
     * @param clientPrincipal        the authenticated client principal
     * @param additionalParameters   the additional parameters
     */
    protected PasswordGrantAuthenticationToken(Authentication clientPrincipal, Map<String, Object> additionalParameters) {
        super(new AuthorizationGrantType(OAuth2Constant.GRANT_TYPE_PASSWORD), clientPrincipal, additionalParameters);
    }
}
