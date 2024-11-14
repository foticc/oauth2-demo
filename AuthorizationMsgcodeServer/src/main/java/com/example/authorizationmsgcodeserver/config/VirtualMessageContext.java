package com.example.authorizationmsgcodeserver.config;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class VirtualMessageContext {

    private static final VirtualMessageContext instance = new VirtualMessageContext();

    private Map<String,String> messages = new ConcurrentHashMap<>();


    private VirtualMessageContext() {}

    public static VirtualMessageContext getInstance() {
        return instance;
    }

    public String message(String user) {
        String string = UUID.randomUUID().toString();
        messages.put(user,string);
        return string;
    }

    public String getMessage(String user) {
        return messages.get(user);
    }

}
