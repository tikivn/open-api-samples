#Overview
This sample demonstrates a Java Spring MVC web app that get access token from Tiki Marketplace using the Spring Security and OAuth2 client library for Java.

#Setup
Dependencies
- spring-boot-starter-security
- spring-boot-starter-oauth2-client

Configure the client app to use public/in-house app.
- Open the src\main\resources\application-oauth2.properties file.
- Fill your client app's credentials (client-id and secret)

 ```java
    tiki provider registration
    spring.security.oauth2.client.registration.tiki.client-id=3750874604017xxx
    spring.security.oauth2.client.registration.tiki.client-secret=GpD1qJ6GMpg0zfiyKTeUQTJ2ofxxxx

    another provider registration
    spring.security.oauth2.client.registration.another.client-id=3750874604017xxx
    spring.security.oauth2.client.registration.another.client-secret=GpD1qJ6GMpg0zfiyKTeUQTJ2ofxxx
```

Define the OAuth2 provider configuration 

``` java
public enum CustomOAuthProvider {

    TIKI {

        @Override
        public Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(registrationId,
                    ClientAuthenticationMethod.CLIENT_SECRET_POST, "{baseUrl}/callback");
            builder.scope("order", "product", "inventory", "multichannel", "offline");
            builder.authorizationUri("https://api.tiki.vn/sc/oauth2/auth");
            builder.tokenUri("https://api.tiki.vn/sc/oauth2/token");
            builder.userInfoUri("https://api.tiki.vn/integration/v2/sellers/me");
            builder.userNameAttributeName("name");
            builder.clientName("Tiki");
            return builder;
        }

    },

    ANOTHER {

        @Override
        public Builder getBuilder(String registrationId) {
            ClientRegistration.Builder builder = getBuilder(registrationId,
                    ClientAuthenticationMethod.CLIENT_SECRET_BASIC, DEFAULT_REDIRECT_URL);
            builder.scope("open");
            builder.authorizationUri("https://api.tiki.vn/sc/oauth2/auth");
            builder.tokenUri("https://api.tiki.vn/sc/oauth2/token");
            builder.clientName("Another");
            return builder;
        }

    };

    private static final String DEFAULT_REDIRECT_URL = "{baseUrl}/{action}/oauth2/code/{registrationId}";

    protected final ClientRegistration.Builder getBuilder(String registrationId, ClientAuthenticationMethod method,
                                                          String redirectUri) {
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId);
        builder.clientAuthenticationMethod(method);
        builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
        builder.redirectUri(redirectUri);
        return builder;
    }

    /**
     * Create a new
     * {@link org.springframework.security.oauth2.client.registration.ClientRegistration.Builder
     * ClientRegistration.Builder} pre-configured with provider defaults.
     * @param registrationId the registration-id used with the new builder
     * @return a builder instance
     */
    public abstract ClientRegistration.Builder getBuilder(String registrationId);

}

```

You must define the token endpoint auth method ClientAuthenticationMethod (CLIENT_SECRET_POST or CLIENT_SECRET_BASIC) corresponding to it in your app registration (Tiki console). 
And "redirect_uri" (for example "{baseUrl}/callback") match one of the OAuth 2.0 Client's pre-registered redirect urls


# Configuration

Define **ClientRegistrationRepository, AuthorizedClientService** beans and their dependency injection


``` java
@Configuration
@EnableWebSecurity
@PropertySource("classpath:application-oauth2.properties")
public class SecurityConfig extends WebSecurityConfigurerAdapter {

   private final Environment env;

   public SecurityConfig(Environment env) {
       this.env = env;
   }

    private static final List<String> clients = Arrays.asList("tiki", "another");

@Bean
public ClientRegistrationRepository clientRegistrationRepository() {
   List<ClientRegistration> registrations = clients.stream()
           .map(this::getRegistration)
           .filter(Objects::nonNull)
           .collect(Collectors.toList());

   return new  InMemoryClientRegistrationRepository(registrations);
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
}
```

## Config OAuth2 Client

```java
@Configuration
@EnableWebSecurity
@PropertySource("classpath:application-oauth2.properties")
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
   @Override
   protected void configure(HttpSecurity http) throws Exception {
       http
               .oauth2Login()
                   .loginPage("/oauth/login") // login page
                   .redirectionEndpoint()
                       .baseUri("/callback") // customize callback url
                   .and()
                   .authorizationEndpoint()
                       .baseUri("/oauth2/authorize-client") // customize authorize url
                   .and()
                   .defaultSuccessUrl("/oauth/authorized", true)
       ;
   }
}
```

* Declare uri that serve login page (/oauth/login)

* If you don't use the default redirect_uri(DEFAULT_REDIRECT_URL = "{baseUrl}/{action}/oauth2/), you need to customize redirectionEndpoint as your own redirect_uri.


# OAuth login page
Implementing Controller returns a list of authorization endpoints (for example */oauth2/authorize-client/tiki, /oauth2/authorize-client/another*) as well as an oauth2 login template (view).

``` java

@Controller
@RequiredArgsConstructor
public class OAuthController {

    private static final String authorizationRequestBaseUri = "/oauth2/authorize-client";

    private final ClientRegistrationRepository clientRegistrationRepository;

    private final OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/oauth/login")
    public String getLoginPage(Model model) {
        Map<String, String> oauth2AuthenticationUrls = new HashMap<>();
        Iterable<ClientRegistration> clientRegistrations = null;
        ResolvableType type = ResolvableType.forInstance(clientRegistrationRepository).as(Iterable.class);
        if (type != ResolvableType.NONE && ClientRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) {
            clientRegistrations = (Iterable<ClientRegistration>) clientRegistrationRepository;
        }

        clientRegistrations.forEach(registration -> oauth2AuthenticationUrls.put(registration.getClientName(), authorizationRequestBaseUri + "/" + registration.getRegistrationId()));
        model.addAttribute("urls", oauth2AuthenticationUrls);

        return "oauth_login";
    }


```

Template (View) for "oauth_login"

```java 
<body>
<div class="container">
   <div class="col-sm-3 well">
       <div class="list-group">
           <h1>We want to access your data from e-commerce platforms. "Click to allow"</h1>
           <p th:each="url : ${urls}">
               <a th:text="${url.key}" th:href="${url.value}" class="list-group-item active"></a>
           </p>
       </div>
   </div>
</div>
</body>
```

The links to authorization endpoints will look like

``` java
   <a href="/oauth2/authorize-client/tiki">Tiki</a>
   <a href="/oauth2/authorize-client/another">Another</a>
```

# Handle success authorization code flow and store tokens

```java
   @GetMapping("/oauth/authorized")
   public String handleSuccessLogin(OAuth2AuthenticationToken oAuth2AuthenticationToken) {
       String appId = oAuth2AuthenticationToken.getAuthorizedClientRegistrationId();
       OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(
               appId, oAuth2AuthenticationToken.getName());
       OAuth2AccessToken accessToken = client.getAccessToken();
       OAuth2RefreshToken refreshToken = client.getRefreshToken();
       oAuthTokenService.storeTokens(appId, accessToken, refreshToken);

       return "index";
   }
}
```

# Call Tiki APIs with access token

Create TikiAPI class 

```java
public abstract class AbstractAccessTokenApi {
    
    protected RestTemplate restTemplate;

    public AbstractAccessTokenApi(String accessToken) {
        this.restTemplate = new RestTemplate();
        if (accessToken != null) {
            this.restTemplate.getInterceptors()
                    .add(getBearerTokenInterceptor(accessToken));
        } else {
            this.restTemplate.getInterceptors().add(getNoTokenInterceptor());
        }
    }

    private ClientHttpRequestInterceptor getBearerTokenInterceptor(String accessToken) {
        ClientHttpRequestInterceptor interceptor = (request, bytes, execution) -> {
            request.getHeaders().add("Authorization", "Bearer " + accessToken);
            return execution.execute(request, bytes);
        };
        return interceptor;
    }

    private ClientHttpRequestInterceptor getNoTokenInterceptor() {
        return (request, bytes, execution) -> {
            throw new IllegalStateException(
                    "Can't access the API without an access token");
        };
    }

}

public class TikiApi extends AbstractAccessTokenApi {
    private static final String SELLER_BASE_URL = "https://api.tiki.vn/integration/v2/sellers";

    public TikiApi (String accessToken) {
        super(accessToken);
    }

    public String getSeller() {
        return restTemplate.getForObject(
                SELLER_BASE_URL + "/me", String.class);
    }
}

```

Define **TikiApi** beans and their dependency injection

```java
    @Bean
    @RequestScope
    public TikiApi tikiApi(OAuthTokenService oAuthTokenService) {
        String accessToken = oAuthTokenService.getAccessToken("tiki");
        return new TikiApi(accessToken);
    }
}
```

Test TikiAPI
```java
@RequiredArgsConstructor
@RestController
public class SellerController {
    private final TikiApi tikiApi;

    @GetMapping("/seller")
    public String getSeller() {
        String seller = tikiApi.getSeller();
        return seller;
    }

}
}
```
