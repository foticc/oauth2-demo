package com.example.authorizationmsgcodeserver.msg;

import com.example.authorizationmsgcodeserver.config.OAuth2Constant;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * 将请求转换为OAuth2AuthorizationGrantAuthenticationToken
 */
public class MessageCodeAuthenticationConverter implements AuthenticationConverter {
    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!StringUtils.hasText(grantType) &&
                !OAuth2Constant.GRANT_TYPE_MESSAGE_CODE.equals(grantType)) {
            return null;
        }


        MultiValueMap<String, String> parameters = getParameters(request);

        String msgCode = parameters.getFirst(OAuth2Constant.PARAMETER_NAME_MESSAGE_CODE);
        if (!StringUtils.hasText(msgCode) ||
                parameters.get(OAuth2Constant.PARAMETER_NAME_MESSAGE_CODE).size() != 1) {
            throw new OAuth2AuthenticationException("无效请求，验证码不能为空！");
        }
        //收集要传入GrantAuthenticationToken构造方法的参数，
        //该参数接下来在GrantAuthenticationProvider中使用
        Map<String, Object> additionalParameters = new HashMap<>();
        //遍历从request中提取的参数，排除掉grant_type、client_id、code等字段参数，其他参数收集到additionalParameters中
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                    !key.equals(OAuth2ParameterNames.CLIENT_ID) &&
                    !key.equals(OAuth2ParameterNames.CODE)) {
                additionalParameters.put(key, value.get(0));
            }
        });
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        return new MessageCodeGrantAuthenticationToken(clientPrincipal,additionalParameters);
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
