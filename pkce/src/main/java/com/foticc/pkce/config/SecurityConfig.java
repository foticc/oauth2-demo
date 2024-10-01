package com.foticc.pkce.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        http.exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint("/login"), new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));
        return http.cors(Customizer.withDefaults())
                .build();
    }


    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize.anyRequest()
                        .authenticated())
                .formLogin(Customizer.withDefaults());
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
                                        "http://127.0.0.1:3000",
                                        "http://192.168.160.1:3000/"
                                ));
                            }
                        })
                        .postLogoutRedirectUri("http://127.0.0.1:9000/logout")
                        .scope(OidcScopes.OPENID).scope(OidcScopes.EMAIL)
                        .scope(OidcScopes.PROFILE)
                        .clientSettings(
                                ClientSettings.builder()
                                        .requireAuthorizationConsent(true)
                                        .requireProofKey(true)
                                        .build()
                        )
                        .build();
        return new InMemoryRegisteredClientRepository(oidcClient);
    }


    @Bean
    UserDetailsService userDetailsService() {
        PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        UserDetails userDetails = User.builder()
                .username("admin")
                .password("123456")
                .passwordEncoder(passwordEncoder::encode)
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        config.addAllowedOrigin("http://127.0.0.1:3000");
        config.setAllowCredentials(true);
        source.registerCorsConfiguration("/**", config);
        return source;
    }


}
