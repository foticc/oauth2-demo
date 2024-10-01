package com.example.authorizationpasswordserver.password;

import com.example.authorizationpasswordserver.config.OAuth2Constant;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

public class PasswordAuthenticationConverter implements AuthenticationConverter {


    public PasswordAuthenticationConverter() {
    }


    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!OAuth2Constant.GRANT_TYPE_PASSWORD.equals(grantType)) {
            return null;
        }

        MultiValueMap<String, String> parameters = getParameters(request);

        String username = parameters.getFirst(OAuth2ParameterNames.USERNAME);
        if (!StringUtils.hasText(username) || parameters.get(OAuth2ParameterNames.USERNAME).size()!=1) {
            throw new OAuth2AuthenticationException("无效请求，用户名不能为空。");
        }

        String password = parameters.getFirst(OAuth2ParameterNames.PASSWORD);
        if (!StringUtils.hasText(password) || parameters.get(OAuth2ParameterNames.PASSWORD).size()!=1) {
            throw new OAuth2AuthenticationException("无效请求，密码不能为空。");
        }

        //收集要传入PasswordGrantAuthenticationToken构造方法的参数，
        //该参数接下来在PasswordGrantAuthenticationProvider中使用
        Map<String, Object> additionalParameters = new HashMap<>();
        //遍历从request中提取的参数，排除掉grant_type、client_id、code等字段参数，其他参数收集到additionalParameters中
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                    !key.equals(OAuth2ParameterNames.SCOPE) &&
                    !key.equals(OAuth2ParameterNames.CODE)) {
                additionalParameters.put(key, value.get(0));
            }
        });

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();


        return new PasswordGrantAuthenticationToken(authentication,additionalParameters);
    }

    /**
     *从request中提取请求参数，然后存入MultiValueMap<String, String>
     */
    private static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            for (String value : values) {
                parameters.add(key, value);
            }
        });
        return parameters;
    }

}
