package com.foticc.pkce.config;

import com.foticc.pkce.handler.FormAuthenticationFailureHandler;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CorsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2TokenEndpointConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.OAuth2DeviceAuthorizationEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2DeviceVerificationEndpointFilter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.server.ui.LoginPageGeneratingWebFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * @see org.springframework.security.oauth2.server.authorization.web.OAuth2AuthorizationEndpointFilter /oauth2/authorize
 * @see org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter  /oauth2/token
 * @see OAuth2DeviceAuthorizationEndpointFilter /oauth2/device_authorization
 * @see OAuth2DeviceVerificationEndpointFilter  /oauth2/device_verification
 * @see DefaultLoginPageGeneratingFilter  默认登录页面
 * @see org.springframework.security.oauth2.server.authorization.web.DefaultConsentPage;
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .authorizationEndpoint(endpoints -> {
                    endpoints.consentPage(CUSTOM_CONSENT_PAGE_URI);
                })
                .oidc(Customizer.withDefaults());
        http.exceptionHandling((exceptions) ->
                        exceptions.defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint("/auth/page"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));
        return http.cors(Customizer.withDefaults())
                .csrf(CsrfConfigurer::disable)
                .build();
    }


    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.formLogin(form ->
                        form.loginPage("/auth/page").loginProcessingUrl("/login")
                                .failureHandler(new FormAuthenticationFailureHandler())
                )
                .authorizeHttpRequests((authorize) -> authorize.requestMatchers("/auth/page", "/login").permitAll().anyRequest().authenticated())
                .logout(new Customizer<LogoutConfigurer<HttpSecurity>>() {
                    @Override
                    public void customize(LogoutConfigurer<HttpSecurity> httpSecurityLogoutConfigurer) {
                        httpSecurityLogoutConfigurer.logoutRequestMatcher(new AntPathRequestMatcher("/logout", HttpMethod.GET.name()));
                    }
                });
//                .formLogin(Customizer.withDefaults());
        http.sessionManagement(httpSecuritySessionManagementConfigurer -> {
            // 仅在需要的时候创建
            httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
        });
        return http.cors(Customizer.withDefaults())
                .build();
    }


    @Bean
    public RegisteredClientRepository registeredClientRepository() {
//        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("oidc-client")
//                .clientSecret("{noop}secret")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
//                .postLogoutRedirectUri("http://127.0.0.1:8080/")
//                .scope(OidcScopes.OPENID)
//                .scope(OidcScopes.PROFILE)
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//                .build();
//        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("oidc-client")
//                //{noop}开头，表示“secret”以明文存储
//                .clientSecret("{noop}secret")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                //.redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
//                //将上面的redirectUri地址注释掉，改成下面的地址，是因为我们暂时还没有客户端服务，以免重定向跳转错误导致接收不到授权码
//                .redirectUri("http://www.baidu.com")
//                //退出操作，重定向地址，暂时也没遇到
//                .postLogoutRedirectUri("http://127.0.0.1:8080/")
//                //设置客户端权限范围
//                .scope(OidcScopes.OPENID)
//                .scope(OidcScopes.PROFILE)
//                //客户端设置用户需要确认授权
//                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
//                .build();
//        //配置基于内存的客户端信息
//        return new InMemoryRegisteredClientRepository(oidcClient);
        RegisteredClient device = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("device-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .redirectUri("http://127.0.0.1:9000/index")
                .scopes(new Consumer<Set<String>>() {
                    @Override
                    public void accept(Set<String> strings) {
                        strings.addAll(Set.of(
                                OidcScopes.OPENID,
                                OidcScopes.EMAIL,
                                OidcScopes.PROFILE,
                                OidcScopes.ADDRESS, OidcScopes.PHONE
                        ));
                    }
                }).tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(2)).build())
                .build();
        RegisteredClient oidcClient =
                RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("public-client")
                        .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUris(new Consumer<Set<String>>() {
                            @Override
                            public void accept(Set<String> strings) {
                                strings.addAll(Set.of(
                                        "http://127.0.0.1:9000/index",
                                        "http://127.0.0.1:3000/",
                                        "http://127.0.0.1:3000/login",
                                        "http://127.0.0.1:3000/callback",
                                        "http://127.0.0.1:3000/default",
                                        "http://127.0.0.1:3000/home",
                                        "http://192.168.31.141:3000/callback",
                                        "http://192.168.160.1:3000/",
                                        "http://192.168.1.63:3000/",
                                        "http://127.0.0.1:9000/index/hello",
                                        "http://192.168.1.63:3000/login",
                                        "http://127.0.0.1:4201/",
                                        "http://127.0.0.1:4201/login/login-form",
                                        "http://127.0.0.1:4201/default",
                                        "http://127.0.0.1:4201/login/callback"
                                ));
                            }
                        })
                        .postLogoutRedirectUris(new Consumer<Set<String>>() {
                            @Override
                            public void accept(Set<String> urls) {
                                urls.addAll(
                                        Set.of(
                                                "http://192.168.1.63:3000/",
                                                "http://127.0.0.1:3000/",
                                                "http://127.0.0.1:4201"
                                        )

                                );
                            }
                        })
                        .scope(OidcScopes.OPENID).scope(OidcScopes.EMAIL)
                        .scope(OidcScopes.PROFILE)
                        .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(2)).build())
                        .clientSettings(
                                ClientSettings.builder()
                                        .requireAuthorizationConsent(true)
                                        .requireProofKey(true)
                                        .build()
                        )
                        .build();
        return new InMemoryRegisteredClientRepository(oidcClient, device);
    }


    @Bean
    UserDetailsService userDetailsService() {
        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        UserDetails admin = User.builder()
                .username("admin")
                .password("123456")
                .passwordEncoder(passwordEncoder::encode)
                .roles("USER")
                .authorities("admin")
                .build();
        UserDetails user = User.builder()
                .username("user")
                .password("123456")
                .passwordEncoder(passwordEncoder::encode)
                .roles("USER")
                .authorities("user")
                .build();

        return new InMemoryUserDetailsManager(admin,user);
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        config.setAllowedOrigins(List.of("http://192.168.31.141:3000/", "http://127.0.0.1:3000","http://127.0.0.1:4201",  "http://192.168.1.63:3000"));
        config.setAllowCredentials(true);
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    public OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    /**
     * 授权确认
     * 对应表：oauth2_authorization_consent
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService() {
        return new InMemoryOAuth2AuthorizationConsentService();
    }

    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer() {
        return new OAuth2TokenCustomizer<JwtEncodingContext>() {
            @Override
            public void customize(JwtEncodingContext context) {
                // 检查登录用户信息是不是UserDetails，排除掉没有用户参与的流程
                if (context.getPrincipal().getPrincipal() instanceof UserDetails user) {
                    // 获取申请的scopes
                    Set<String> scopes = context.getAuthorizedScopes();
                    // 获取用户的权限
                    Collection<? extends GrantedAuthority> authorities = user.getAuthorities();
                    // 提取权限并转为字符串
                    Set<String> authoritySet = Optional.ofNullable(authorities).orElse(Collections.emptyList()).stream()
                            // 获取权限字符串
                            .map(GrantedAuthority::getAuthority)
                            // 去重
                            .collect(Collectors.toSet());

                    // 合并scope与用户信息
                    authoritySet.addAll(scopes);

                    JwtClaimsSet.Builder claims = context.getClaims();

                    // 将权限信息放入jwt的claims中（也可以生成一个以指定字符分割的字符串放入）
                    claims.claim("authorities", authoritySet);

                    // todo 只是在测试的
                    if(user.getUsername().equals("admin")) {
                        claims.claim("uid", 3);
                    }else {
                        claims.claim("uid", 4);
                    }

                    // 放入其它自定内容
                    // 角色、头像...
                }
            }
        };
    }


}
