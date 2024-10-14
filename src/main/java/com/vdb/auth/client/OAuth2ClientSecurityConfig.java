package com.vdb.auth.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

import static org.springframework.security.config.Customizer.withDefaults;


@Configuration
@EnableWebSecurity
@EnableAsync
public class OAuth2ClientSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           OAuth2AuthorizedClientService authorizedClientService,
                                           LoggingFilter loggingFilter,
                                           ClientRegistrationRepository clientRegistrationRepository) throws Exception {
//        http
//                .oauth2Client(oauth2 -> oauth2
//                        .clientRegistrationRepository(this.clientRegistrationRepository())
//                        .authorizedClientRepository(this.authorizedClientRepository())
//                        .authorizedClientService(this.authorizedClientService(this.clientRegistrationRepository()))
//                        .authorizationCodeGrant(codeGrant -> codeGrant
//                                .authorizationRequestRepository(this.authorizationRequestRepository())
//                                .authorizationRequestResolver(this.authorizationRequestResolver(this.clientRegistrationRepository()))
//                                .accessTokenResponseClient(this.accessTokenResponseClient())
//                        )
//                );
        http
                .addFilterBefore(loggingFilter, UsernamePasswordAuthenticationFilter.class)
                .cors(c -> c.configurationSource(corsConfigurationSource())) // Enable CORS
                .csrf(c -> c.disable()) // Disable CSRF if necessary
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(successHandler(authorizedClientService))
                        .authorizationEndpoint(authorization -> authorization
                                .authorizationRequestResolver(authorizationRequestResolver(clientRegistrationRepository))  // Set custom resolver
                        )
                );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://app.localtest.me:4200",
                "http://auth-server.localtest.me:9000"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public AuthenticationSuccessHandler successHandler(OAuth2AuthorizedClientService authorizedClientService) {
        return (request, response, authentication) -> {
            OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) authentication;
            OAuth2AuthorizedClient authorizedClient = authorizedClientService
                    .loadAuthorizedClient(authToken.getAuthorizedClientRegistrationId(), authToken.getName());

            String accessToken = authorizedClient.getAccessToken().getTokenValue();
            String refreshToken = authorizedClient.getRefreshToken() != null ? authorizedClient.getRefreshToken().getTokenValue() : null;
            String idToken = ((OidcUser) authToken.getPrincipal()).getIdToken().getTokenValue(); // Retrieve the ID token if available
            addCookieWithSameSite(response, "access_token", accessToken, true);
            addCookieWithSameSite(response, "refresh_token", refreshToken, true);
            addCookieWithSameSite(response, "id_token", idToken, false);
            response.setHeader("Access-Control-Allow-Origin", "http://app.localtest.me:4200");  // Or wildcard "*" for all origins
            response.setHeader("Access-Control-Allow-Credentials", "true");  // Allow credentials to be sent
            // Handle state parameter
            String state = request.getParameter("state");
            if (state != null) {
                try {
                    // Decode the state parameter (assuming it's base64 encoded)
                    String decodedState = new String(Base64.getDecoder().decode(state), StandardCharsets.UTF_8);

                    // Extract customPage from the decoded JSON state
                    ObjectMapper objectMapper = new ObjectMapper();
                    Map<String, String> stateData = objectMapper.readValue(decodedState, Map.class);
                    String customPage = stateData.get("customPage"); // The original page

                    // Redirect to the original custom page
                    if (customPage != null) {
                        response.sendRedirect(customPage);
                        return;  // Avoid redirecting twice
                    }

                } catch (IllegalArgumentException e) {
                    // Handle invalid base64 input (e.g., log the error)
                    System.out.println("Failed to decode state parameter: " + e.getMessage());
                } catch (Exception e) {
                    // Handle JSON parsing errors or other issues
                    System.out.println("Failed to parse decoded state: " + e.getMessage());
                }
            }

            // Fallback redirect if state is not present or decoding fails
            response.sendRedirect("http://app.localtest.me:4200/seller/create-car");
        };
    }

    private void addCookieWithSameSite(HttpServletResponse response, String name, String value, boolean httpOnly) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(httpOnly);
        cookie.setPath("/");  // Ensure the path is correct
        cookie.setMaxAge(3600); // Set expiration
        cookie.setSecure(false);  // For development, set to true for HTTPS in production
        cookie.setDomain("localtest.me");

        // Add the cookie to the response
        response.addCookie(cookie);
    }

    @Bean
    public OAuth2AuthorizationRequestResolver authorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository) {
        DefaultOAuth2AuthorizationRequestResolver defaultResolver =
                new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI);

        // Return your custom resolver with the default resolver passed as a parameter
        return new CustomAuthorizationRequestResolver(defaultResolver);
    }
}