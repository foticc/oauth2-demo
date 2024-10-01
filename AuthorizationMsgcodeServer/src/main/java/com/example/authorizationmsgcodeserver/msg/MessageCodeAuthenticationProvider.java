package com.example.authorizationmsgcodeserver.msg;

import com.example.authorizationmsgcodeserver.config.OAuth2Constant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
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
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import java.security.Principal;
import java.util.IllegalFormatCodePointException;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class MessageCodeAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private static final Logger logger = LoggerFactory.getLogger(MessageCodeAuthenticationProvider.class);
    private final UserDetailsService userDetailsService;

    private final OAuth2AuthorizationService authorizationService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

    public MessageCodeAuthenticationProvider(UserDetailsService userDetailsService,
                                             OAuth2AuthorizationService authorizationService,
                                             OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
        this.userDetailsService = userDetailsService;
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        MessageCodeGrantAuthenticationToken authenticationToken = (MessageCodeGrantAuthenticationToken) authentication;

        // 授权类型
        AuthorizationGrantType grantType = authenticationToken.getGrantType();



        Map<String, Object> additionalParameters = authenticationToken.getAdditionalParameters();

        String username = (String) additionalParameters.get(OAuth2ParameterNames.USERNAME);
        String msg = (String) additionalParameters.get(OAuth2Constant.PARAMETER_NAME_MESSAGE_CODE);
        //请求参数权限范围
        String requestScopesStr = (String)additionalParameters.get(OAuth2ParameterNames.SCOPE);
        //请求参数权限范围专场集合
        Set<String> requestScopeSet = Stream.of(requestScopesStr.split(" ")).collect(Collectors.toSet());


        // client 是否认证
        OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(authenticationToken);

        // client 是否支持此种认证模式
        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (registeredClient == null || !registeredClient.getAuthorizationGrantTypes().contains(grantType)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }
        // 其它处理
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        if (!"123".equals(msg)) {
            throw new OAuth2AuthenticationException("验证码不正确");
        }


        UsernamePasswordAuthenticationToken authenticated =
                UsernamePasswordAuthenticationToken.authenticated(userDetails, clientPrincipal, userDetails.getAuthorities());

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authenticated)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizationGrantType(grantType)
                .authorizedScopes(requestScopeSet)
                .authorizationGrant(authenticationToken);

        OAuth2Authorization.Builder authorizationBuilder  = OAuth2Authorization.withRegisteredClient(registeredClient)
                .principalName(clientPrincipal.getName())
                .authorizedScopes(requestScopeSet)
                .attribute(Principal.class.getName(), authenticated)
                .authorizationGrantType(grantType);

        // access_token
        DefaultOAuth2TokenContext tokenContext =
                tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);
        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }
        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
                generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
        if (generatedAccessToken instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generatedAccessToken).getClaims()));
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        // ----- Refresh token -----
        OAuth2RefreshToken refreshToken = null;
        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
                // Do not issue refresh token to public client
                !clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {

            tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);
            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                        "The token generator failed to generate the refresh token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }

            if (logger.isTraceEnabled()) {
                logger.trace("Generated refresh token");
            }

            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            authorizationBuilder.refreshToken(refreshToken);
        }

       //保存认证信息
        OAuth2Authorization authorization = authorizationBuilder.build();
        this.authorizationService.save(authorization);

        if (logger.isTraceEnabled()) {
            logger.trace("Saved authorization");
        }

        if (logger.isTraceEnabled()) {
            logger.trace("Authenticated token request");
        }

        return  new OAuth2AccessTokenAuthenticationToken(
                registeredClient, clientPrincipal, accessToken, refreshToken, additionalParameters);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MessageCodeGrantAuthenticationToken.class.isAssignableFrom(authentication);
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
