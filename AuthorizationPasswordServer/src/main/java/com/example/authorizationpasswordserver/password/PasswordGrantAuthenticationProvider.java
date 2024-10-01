package com.example.authorizationpasswordserver.password;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

import java.util.Map;

public class PasswordGrantAuthenticationProvider implements AuthenticationProvider {

    private static final Logger logger = LoggerFactory.getLogger(PasswordGrantAuthenticationProvider.class);
    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private final UserDetailsService userDetailsService;

    private final PasswordEncoder passwordEncoder;

    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    public PasswordGrantAuthenticationProvider(UserDetailsService userDetailsService,
                                               PasswordEncoder passwordEncoder,
                                               OAuth2AuthorizationService authorizationService,
                                               OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        Assert.notNull(authorizationService,"authorizationService cannot be null");
        Assert.notNull(tokenGenerator,"tokenGenerator cannot be null");
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        PasswordGrantAuthenticationToken passwordGrantAuthenticationToken = (PasswordGrantAuthenticationToken) authentication;

        Map<String, Object> additionalParameters = passwordGrantAuthenticationToken.getAdditionalParameters();

        // grant_type
        AuthorizationGrantType grantType = passwordGrantAuthenticationToken.getGrantType();

        // username
        String username = (String) additionalParameters.get(OAuth2ParameterNames.USERNAME);
        // password
        String password = (String) additionalParameters.get(OAuth2ParameterNames.PASSWORD);


        OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(authentication);

        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
        // 如果客户端不包含 此种认证模式
        if (registeredClient!=null && !registeredClient.getAuthorizationGrantTypes().contains(grantType)){
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        if (!passwordEncoder.matches(password,userDetails.getPassword())) {
            throw new OAuth2AuthenticationException("密码不正确");
        }

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(clientPrincipal)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizationGrantType(grantType)
                .authorizationGrant(passwordGrantAuthenticationToken);

        OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();

        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);

        if (generatedAccessToken == null) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.",null));
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(),
                generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(), null);

        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(clientPrincipal.getName())
                .authorizationGrantType(grantType);

        if (generatedAccessToken instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken, stringObjectMap ->
                    stringObjectMap.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generatedAccessToken).getClaims()));
        }else {
            authorizationBuilder.accessToken(accessToken);
        }
        // 添加refresh_token @see org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationProvider
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (generatedRefreshToken != null) {
                if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                    OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                            "The token generator failed to generate a valid refresh token.", ERROR_URI);
                    throw new OAuth2AuthenticationException(error);
                }

                if (logger.isTraceEnabled()) {
                    logger.trace("Generated refresh token");
                }

                refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
                authorizationBuilder.refreshToken(refreshToken);
            }
        }
        OAuth2Authorization build = authorizationBuilder.build();
        this.authorizationService.save(build);
        return new OAuth2AccessTokenAuthenticationToken(registeredClient,clientPrincipal,accessToken,refreshToken);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return PasswordGrantAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }
}
