package com.example.javaoauth2client.config;

import com.example.javaoauth2client.oauth2.registration.ClientRegistration;
import com.example.javaoauth2client.oauth2.registration.ClientRegistrationRepository;
import com.example.javaoauth2client.oauth2.registration.InMemoryClientRegistrationRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.web.client.RestTemplate;

import java.util.*;
import java.util.stream.Collectors;

@Configuration
@PropertySource("classpath:application-oauth2.properties")
public class ClientRegistrationConfig {

    private final Environment env;

    public ClientRegistrationConfig(Environment env) {
        this.env = env;
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        List<String> clients = Arrays.asList("tiki", "another");
        List<ClientRegistration> registrations = clients.stream()
                .map(this::getRegistration)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        return new InMemoryClientRegistrationRepository(registrations);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    private ClientRegistration getRegistration(String client) {
        String CLIENT_PROPERTY_KEY = "oauth2.client.registration.";
        String appId = env.getProperty(CLIENT_PROPERTY_KEY + client + ".app-id");
        if (appId == null) {
            return null;
        }

        String clientId = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-id");
        String clientSecret = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-secret");
        ClientRegistration.ClientAuthenticationMethod clientAuthenticationMethod = ClientRegistration.ClientAuthenticationMethod.fromString(
                env.getProperty(CLIENT_PROPERTY_KEY + client + ".authentication-method"));
        String redirectUri = env.getProperty(CLIENT_PROPERTY_KEY + client + ".redirect-uri");
        Set<String> scopes = new HashSet<>(Arrays.asList(Objects.requireNonNull(env.getProperty(CLIENT_PROPERTY_KEY + client + ".scopes")).split(",")));
        String authorizationUri = env.getProperty(CLIENT_PROPERTY_KEY + client + ".authorization-uri");
        String tokenUri = env.getProperty(CLIENT_PROPERTY_KEY + client + ".token-uri");
        String userInfoUri = env.getProperty(CLIENT_PROPERTY_KEY + client + ".user-info-uri");

        return ClientRegistration.builder()
                .registrationId(appId)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .clientAuthenticationMethod(clientAuthenticationMethod)
                .redirectUri(redirectUri)
                .scopes(scopes)
                .authorizationUri(authorizationUri)
                .tokenUri(tokenUri)
                .userInfoUri(userInfoUri)
                .build();
    }

    @Bean
    @RequestScope
    public TikiApi tikiApi(OAuthTokenService oAuthTokenService) {
        String accessToken = oAuthTokenService.getAccessToken("tiki");
        return new TikiApi(accessToken);
    }
}
