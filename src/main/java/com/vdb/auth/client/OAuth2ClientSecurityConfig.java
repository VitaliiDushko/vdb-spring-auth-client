package com.vdb.auth.client;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;


@Configuration
@EnableWebSecurity
@EnableAsync
public class OAuth2ClientSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
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
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .oauth2Login(withDefaults());

        return http.build();
    }
}