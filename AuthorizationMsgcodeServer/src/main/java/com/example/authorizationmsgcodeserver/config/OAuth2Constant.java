package com.example.authorizationmsgcodeserver.config;

public interface OAuth2Constant {

    /**
     * 短信验证码模式（自定义）
     */
    String GRANT_TYPE_MESSAGE_CODE = "authorization_message";
    String PARAMETER_NAME_MESSAGE_CODE = "msg_code";

}
