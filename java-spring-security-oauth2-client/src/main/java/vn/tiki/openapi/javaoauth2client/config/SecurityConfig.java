package vn.tiki.openapi.javaoauth2client.config;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.endpoint.*;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.context.annotation.RequestScope;
import vn.tiki.openapi.javaoauth2client.oauth2.*;
import vn.tiki.openapi.javaoauth2client.service.OAuthTokenService;

@Configuration
@EnableWebSecurity
@PropertySource("classpath:application-oauth2.properties")
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final Environment env;

    public SecurityConfig(Environment env) {
        this.env = env;
    }

    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("tikiseller").password(passwordEncoder().encode("bestseller")).roles("USER")
                ;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/login*").permitAll()
                .and()
                .formLogin()
                    .loginPage("/login.html")
                    .loginProcessingUrl("/perfom_login")
                    .usernameParameter("username")
                    .passwordParameter("password")
                    .defaultSuccessUrl("/index.html", true)
                    .failureUrl("/index.html?error=true")
                .and()
                .oauth2Login()
                    .loginPage("/oauth/login") // login page
                    .authorizedClientService(authorizedClientService())
                    .clientRegistrationRepository(clientRegistrationRepository())
                    .redirectionEndpoint()
                        .baseUri("/callback") // customize callback url
                    .and()
                    .authorizationEndpoint()
                        .baseUri("/oauth2/authorize-client") // customize authorize url
                    .and()
                    .tokenEndpoint()
                        .accessTokenResponseClient(accessTokenResponseClient()) // customize access token client
                    .and()
                    .defaultSuccessUrl("/oauth/authorized", true)
        ;
    }

    @Bean
    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
        return new HttpSessionOAuth2AuthorizationRequestRepository();
    }

    @Bean
    public OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        return new DefaultAuthorizationCodeTokenResponseClient();
    }

    private static final List<String> clients = Arrays.asList("tiki", "another");

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        List<ClientRegistration> registrations = clients.stream()
                .map(this::getRegistration)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        return new InMemoryClientRegistrationRepository(registrations);
    }

    @Bean
    public OAuth2AuthorizedClientService authorizedClientService() {
        return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository());
    }

    private ClientRegistration getRegistration(String client) {
        String CLIENT_PROPERTY_KEY = "spring.security.oauth2.client.registration.";
        String clientId = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-id");

        if (clientId == null) {
            return null;
        }

        String clientSecret = env.getProperty(CLIENT_PROPERTY_KEY + client + ".client-secret");
        if (client.equals("tiki")) {
            return CustomOAuthProvider.TIKI.getBuilder(client)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .scope("inventory", "multichannel", "offline")
                    .build();
        }
        if (client.equals("another")) {
            return CustomOAuthProvider.ANOTHER.getBuilder(client)
                    .clientId(clientId)
                    .clientSecret(clientSecret)
                    .build();
        }
        return null;
    }

    @Bean
    @RequestScope
    public TikiApi tikiApi(OAuthTokenService oAuthTokenService) {
        String accessToken = oAuthTokenService.getAccessToken("tiki");
        return new TikiApi(accessToken);
    }
}