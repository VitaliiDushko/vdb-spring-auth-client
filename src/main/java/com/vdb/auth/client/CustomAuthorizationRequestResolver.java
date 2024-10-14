package com.vdb.auth.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Component
public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

    private final OAuth2AuthorizationRequestResolver defaultResolver;

    public CustomAuthorizationRequestResolver(OAuth2AuthorizationRequestResolver defaultResolver) {
        this.defaultResolver = defaultResolver;
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request);
        return customizeAuthorizationRequest(request, authorizationRequest);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request, clientRegistrationId);
        return customizeAuthorizationRequest(request, authorizationRequest);
    }

    private OAuth2AuthorizationRequest customizeAuthorizationRequest(HttpServletRequest request, OAuth2AuthorizationRequest authorizationRequest) {
        if (authorizationRequest == null) {
            return null;
        }

        // Get Spring's internally generated `state`
        String springGeneratedState = authorizationRequest.getState();

        // Retrieve custom page or any other data you want to preserve from the original request
        String customPage = request.getParameter("customPage");

        // Combine the two in the `state` parameter
        Map<String, String> customState = new HashMap<>();
        customState.put("springState", springGeneratedState);
        customState.put("customPage", customPage);
        ObjectMapper objectMapper = new ObjectMapper();
        String combinedState = springGeneratedState;
        try {
            combinedState = Base64.getEncoder().encodeToString(objectMapper.writeValueAsString(customState).getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            // Handle the error appropriately
        }

        // Create a new OAuth2AuthorizationRequest with the combined state
        return OAuth2AuthorizationRequest.from(authorizationRequest)
                .state(combinedState)
                .build();
    }
}
