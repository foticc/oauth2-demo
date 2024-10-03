package com.foticc.pkce.endpoints;


import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.*;

@Controller
public class IndexEndpoints {

    private Map<String, String> hiddenInputs(HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        return (token != null) ? Collections.singletonMap(token.getParameterName(), token.getToken())
                : Collections.emptyMap();
    }

    @GetMapping("/auth/page")
    public String auth(Model model,HttpServletRequest request) {
        Map<String, String> hidden = this.hiddenInputs(request);
        model.addAttribute("hidden",hidden);
        return "login";
    }

    @GetMapping("/oauth2/consent")
    public String consent(Model model,
                          @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
                          @RequestParam(OAuth2ParameterNames.SCOPE) String scope,
                          @RequestParam(OAuth2ParameterNames.STATE) String state) {
        Set<String> authorizedScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        model.addAttribute(OAuth2ParameterNames.CLIENT_ID,clientId);
        model.addAttribute(OAuth2ParameterNames.SCOPE,authorizedScopes);
        model.addAttribute(OAuth2ParameterNames.STATE,state);
        return "consent";
    }
}
