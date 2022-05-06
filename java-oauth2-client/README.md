# Step 1: Define the OAuth2 provider configuration 
Firstly, we need to define OAuth2 provider configuration (endpoints, token endpoint auth method, redirect-uri, ...)

For example (in Java/Spring) we can put these configuration in src/resources/application-oauth2.properties.

```java
oauth2.client.registration.tiki.app-id=tiki
oauth2.client.registration.tiki.client-id=3750874604017xxx
oauth2.client.registration.tiki.client-secret=vjU62QUEkbh1GH5worP-R088f7ZBxxx
oauth2.client.registration.tiki.authentication-method=client_secret_post
oauth2.client.registration.tiki.redirect-uri=http://localhost:9003/callback
oauth2.client.registration.tiki.scopes=order,multichannel,offline
oauth2.client.registration.tiki.authorization-uri=https://api.tiki.vn/sc/oauth2/auth
oauth2.client.registration.tiki.token-uri=https://api.tiki.vn/sc/oauth2/token
oauth2.client.registration.tiki.user-info-uri=https://api.tiki.vn/integration/v2/sellers/me


oauth2.client.registration.another.app-id=another
oauth2.client.registration.another.client-id=1173926070135313
oauth2.client.registration.another.client-secret=R_-tSbEGOFZsE7hsRQjBN0ni8vvflWPW
oauth2.client.registration.another.authentication-method=client_secret_basic
oauth2.client.registration.another.redirect-uri=http://localhost:9003/callback
oauth2.client.registration.another.scopes=order,product,inventory,multichannel,offline
oauth2.client.registration.another.authorization-uri=https://api.tiki.vn/sc/oauth2/auth
oauth2.client.registration.another.token-uri=https://api.tiki.vn/sc/oauth2/token
oauth2.client.registration.another.user-info-uri=https://api.tiki.vn/integration/v2/sellers/me
```

You must define the token endpoint auth method authentication-method (client_secret_post or client_secret_basic) corresponding to it in your app registration (basic header or body request). And "redirect_uri" (for example "http://localhost:9003/callback") match one of the OAuth 2.0 Client's pre-registered redirect urls

# Step 2: Implement ClientRegistration and a repository hold these ClientRegistration instances 
Implement ClientRegistration.class for OAuth2 providers (Tiki, Another)

```java 
package com.example.javaoauth2client.oauth2.registration;

import lombok.Builder;
import lombok.Getter;

import java.io.Serializable;
import java.util.Set;

@Getter
@Builder
public final class ClientRegistration implements Serializable {

    private final String registrationId;
    private final String clientId;
    private final String clientSecret;
    private final ClientAuthenticationMethod clientAuthenticationMethod;
    private final String redirectUri;
    private final Set<String> scopes;
    private final String authorizationUri;
    private final String tokenUri;
    private final String userInfoUri;

    public enum ClientAuthenticationMethod {
        CLIENT_SECRET_BASIC("client_secret_basic"),
        CLIENT_SECRET_POST("client_secret_post")
        ;

        private final String value;

        ClientAuthenticationMethod(String value) {
            this.value = value;
        }

        public String getValue() {
            return this.value;
        }

        public static ClientAuthenticationMethod fromString(String value) {
            for (ClientAuthenticationMethod c : ClientAuthenticationMethod.values()) {
                if (c.value.equalsIgnoreCase(value)) {
                    return c;
                }
            }

            return CLIENT_SECRET_BASIC;
        }
    }
}
```
Then, implement a repository to hold these client registrations. We should use an in-mem repository that uses a ConcurrentHashMap to hold ClientRegistration instances.


```java
package com.example.javaoauth2client.oauth2.registration;

public interface ClientRegistrationRepository {
    ClientRegistration findByRegistrationId(String var1);
}

package com.example.javaoauth2client.oauth2.registration;


import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class InMemoryClientRegistrationRepository implements ClientRegistrationRepository, Iterable<ClientRegistration> {
    private final Map<String, ClientRegistration> registrations;

    public InMemoryClientRegistrationRepository(ClientRegistration... registrations) {
        this(Arrays.asList(registrations));
    }

    public InMemoryClientRegistrationRepository(List<ClientRegistration> registrations) {
        this(createRegistrationsMap(registrations));
    }

    private static Map<String, ClientRegistration> createRegistrationsMap(List<ClientRegistration> registrations) {
        return toUnmodifiableConcurrentMap(registrations);
    }

    private static Map<String, ClientRegistration> toUnmodifiableConcurrentMap(List<ClientRegistration> registrations) {
        ConcurrentHashMap<String, ClientRegistration> result = new ConcurrentHashMap<>();

        for (ClientRegistration registration : registrations) {
            result.put(registration.getRegistrationId(), registration);
        }

        return Collections.unmodifiableMap(result);
    }

    public InMemoryClientRegistrationRepository(Map<String, ClientRegistration> registrations) {
        this.registrations = registrations;
    }

    public Iterator<ClientRegistration> iterator() {
        return this.registrations.values().iterator();
    }

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
        return this.registrations.get(registrationId);
    }
}
```

Mapping these configurations (from the properties file) into a Java object (ClientRegistration.class), as well as defining ClientRegistrationRepository beans and their dependency injection in **ClientRegistrationConfig** file


```

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
}
```
# Step 3: Define AccessTokenResponse, AuthorizationRequest and TokenResponseClient

Define AccessTokenResponse as the specific response format returned by the token endpoint when obtaining an access token.

```java
@Data
public class AccessTokenResponse {
    @JsonProperty("access_token")
    private String accessToken;

    @JsonProperty("refresh_token")
    private String refreshToken;

    @JsonProperty("expires_in")
    private Long expiresIn;

    @JsonProperty("scope")
    private String scope;
}

```

Define an interface AuthorizationRequest includes 2 methods getBody() and getHeader().
We need specific headers and body in the API request to exchange authorization with the token endpoint server to obtain an access token.

Each specific auth flow (authorization code grant, client credentials, refresh token) has a different body. And depending on which token endpoint auth method you use, we have different headers.

``` java
public interface AuthorizationRequest {
    LinkedMultiValueMap<String, String> getBody();
    String getAuthorizationHeader();
}

```

Define TokenResponseClient as an interface. We'll invoke the method of the interface along with the ClientRegistration instance to obtain an access token corresponding to that ClientRegistration (in the AccessTokenResponse). 

Depending on the type of auth flows (authorization code grant, client credentials, refresh token), we have to pass additional parameters such as code or refresh token to the methods.

```java
public interface TokenResponseClient {
    AccessTokenResponse getAccessTokenByAuthorizationCode(ClientRegistration registration, String code);

    AccessTokenResponse getAccessTokenByRefreshToken(ClientRegistration registration, String refreshToken);

    AccessTokenResponse getAccessTokenByClientCredentials(ClientRegistration registration);
}

```

#Step 4: Obtain access token by client credentials 

With the inhouse app, we only need to implement Client Credentials grant and get an access token without taking care of the next step.

Implement ClientCredentialsRequest to specify the request using client credentials (type of auth flow).

```java
@Data
@Builder
public class ClientCredentialsRequest implements AuthorizationRequest {
    @JsonProperty("grant_type")
    private final String grantType = "client_credentials";

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("client_secret")
    private String clientSecret;

    @Override
    public LinkedMultiValueMap<String, String> getBody() {
        LinkedMultiValueMap<String, String> result = new LinkedMultiValueMap<>();
        result.put("grant_type", Collections.singletonList(grantType));
        result.put("client_id", Collections.singletonList(clientId));
        result.put("client_secret", Collections.singletonList(clientSecret));
        return result;
    }

    @Override
    public String getHeader() {
        String credentials = clientId + ":" + clientSecret;
        return "Basic " + Base64Utils.encodeToString(credentials.getBytes());
    }
}
```

Next, implement detail the method getAccessTokenByClientCredentials() in the TokenResponseClientImpl class.

```java
package com.example.javaoauth2client.oauth2;

import com.example.javaoauth2client.oauth2.registration.ClientRegistration;
import com.example.javaoauth2client.oauth2.token.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Component
@RequiredArgsConstructor
public class TokenResponseClientImpl implements TokenResponseClient {

    private final RestTemplate restTemplate;

    @Override
    public AccessTokenResponse getAccessTokenByClientCredentials(ClientRegistration registration) {
        AuthorizationRequest request = ClientCredentialsRequest.builder()
                .clientId(registration.getClientId())
                .clientSecret(registration.getClientSecret())
                .build();

        RequestEntity<?> requestEntity = getRequestEntity(registration, request);

        ResponseEntity<AccessTokenResponse> response = this.restTemplate.exchange(requestEntity, AccessTokenResponse.class);

        return response.getBody();
    }


    private RequestEntity<?> getRequestEntity(ClientRegistration registration, AuthorizationRequest request) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        if (registration.getClientAuthenticationMethod().equals(ClientRegistration.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
            headers.set("Authorization", request.getHeader());
        }

        LinkedMultiValueMap<String, String> body = request.getBody();

        return RequestEntity
                .post(registration.getTokenUri())
                .headers(headers)
                .body(body);
    }
}

```

Finally, we got an access token. Move to step 8 to see how to use the access token to access Tiki services through APIs.


# Step 5: Get authorization code (in authorization code flow)
We need authorization code (code) to exchange access token with token endpoint.
And to get the code, we need to build an authorization code flow to get authorization from the resource owner.

Firstly, you have to create a page to return a **form** requesting **resource owners**' authorization to grant your client app access to their resources by clicking the link (for example '/oauth2/authorize-client/tiki')

```html
<body>
<div class="container">
   <div class="col-sm-3 well">
       <div class="list-group">
           <h1>We want to access your data from e-commerce platforms. "Click to allow"</h1>
            <a href="/oauth2/authorize-client/tiki">Tiki</a>
            <a href="/oauth2/authorize-client/another">Another</a>
       </div>
   </div>
</div>
</body>

```
Your client app should provide these links as a list through an API or return directly to a pageview. For example as route "/oauth2"

```java
@RestController
@RequiredArgsConstructor
public class OAuthController {
    private static final String authorizationRequestBaseUri = "/oauth2/authorize-client";

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final TokenResponseClient tokenResponseClient;

    @GetMapping("/oauth2")
    public List<String> oauth2() {
        List<String> result = new LinkedList<>();
        Iterable<ClientRegistration> clientRegistrations = null;
        ResolvableType type = ResolvableType.forInstance(clientRegistrationRepository).as(Iterable.class);
        if (type != ResolvableType.NONE && ClientRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) {
            clientRegistrations = (Iterable<ClientRegistration>) clientRegistrationRepository;
        }

        assert clientRegistrations != null;
        Assert.notNull(clientRegistrations, "There's no client registration.");
        clientRegistrations.forEach(registration -> result.add(authorizationRequestBaseUri + "/" + registration.getRegistrationId()));

        return result;
    }

    @GetMapping("/oauth2/authorize-client/{appId}")
    public void redirectToAuthenticationEndpoint(HttpServletResponse response, @PathVariable String appId)
            throws UnsupportedEncodingException {
        ClientRegistration registration = clientRegistrationRepository.findByRegistrationId(appId);
        String authUri = registration.getAuthorizationUri();
        String clientId = registration.getClientId();
        String redirectUri = registration.getRedirectUri();
        String scopes = URLEncoder.encode(String.join(" ", registration.getScopes()), StandardCharsets.UTF_8.toString());
        byte[] array = new byte[16];
        new Random().nextBytes(array);
        String generatedState = new String(array, StandardCharsets.UTF_8);

        response.setHeader("Location",
                String.format("%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s",
                        authUri,clientId, redirectUri, scopes, generatedState));
        response.setStatus(302);
    }

}
```
Note
- You should define the base URI for the authorization request link.such as "/oauth2/authorize-client"
- You should get a list of client-registration IDs from ClientRegistrationRepository (tiki, another). Then, return list of oauth2-client endpoint such as '/oauth2/authorize-client/tiki', '/oauth2/authorize-client/another'
- You have to handle redirects ("/oauth2/authorize-client/{appId}") when a user clicks on a link by @GetMapping("/oauth2/authorize-client/{appId}"). appId corresponding to client registration's ID (tiki, another)

When a user clicks on a link, their browser will be redirected to the Tiki Authentication endpoint or other OAuth2 providers. After OAuth2 providers  authenticate the resource owner and ensure the resource owner's consent with the request from the client app.  OAuth2 providers will redirect the user's browser to a callback (redirect_uri has been pre-defined) along with some parameters such as code or error

You have to handle that callback to get code or handle error. In the successful case, you will have a code. Using the code to exchange access token.

```java
@RestController
@RequiredArgsConstructor
public class OAuthController {
    private static final String authorizationRequestBaseUri = "/oauth2/authorize-client";

    private final ClientRegistrationRepository clientRegistrationRepository;
    private final TokenResponseClient tokenResponseClient;

    @GetMapping("tiki/callback")
    public ResponseEntity<AccessTokenResponse> callback(@RequestParam("code") Optional<String> code,
                                           @RequestParam("error") Optional<String> error,
                                           @RequestParam("error_code") Optional<Integer> errorCode) {

        if (!code.isPresent()) {
            // handle error
        }

        ClientRegistration registration = clientRegistrationRepository.findByRegistrationId("tiki");
        AccessTokenResponse accessToken = tokenResponseClient.getAccessTokenByAuthorizationCode(registration, code.get());

        return ResponseEntity.ok(accessToken);
    }

    @GetMapping("another/callback")
    public ResponseEntity<AccessTokenResponse> callback(@RequestParam("code") Optional<String> code,
                                           @RequestParam("error") Optional<String> error,
                                           @RequestParam("error_code") Optional<Integer> errorCode) {
    
                                
    }
}

```


# Step 6: Obtain access token by authorization code 
Prerequisites
- You have to get a code in Step 5.

Implement AuthorizationCodeGrantRequest to specify the request using authorization code flow (type of auth flow).

```java

@Data
@Builder
public class AuthorizationCodeGrantRequest implements AuthorizationRequest {

    @JsonProperty("grant_type")
    private final String grantType = "authorization_code";

    private String code;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("client_secret")
    private String clientSecret;

    @JsonProperty("redirect_uri")
    private String redirectUri;

    @Override
    public LinkedMultiValueMap<String, String> getBody() {
        LinkedMultiValueMap<String, String> result = new LinkedMultiValueMap<>();
        result.put("grant_type", Collections.singletonList(grantType));
        result.put("client_id", Collections.singletonList(clientId));
        result.put("code", Collections.singletonList(code));
        result.put("redirect_uri", Collections.singletonList(redirectUri));
        result.put("client_secret", Collections.singletonList(clientSecret));
        return result;
    }

    @Override
    public String getHeader() {
        String credentials = clientId + ":" + clientSecret;
        return "Basic " + Base64Utils.encodeToString(credentials.getBytes());
    }
}

```

Next, implement detail the method getAccessTokenByAuthorizationCode() in the TokenResponseClientImpl class.

```java
package com.example.javaoauth2client.oauth2;

import com.example.javaoauth2client.oauth2.registration.ClientRegistration;
import com.example.javaoauth2client.oauth2.token.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Component
@RequiredArgsConstructor
public class TokenResponseClientImpl implements TokenResponseClient {

    private final RestTemplate restTemplate;

    @Override
    public AccessTokenResponse getAccessTokenByAuthorizationCode(ClientRegistration registration, String code) {
        AuthorizationRequest request = AuthorizationCodeGrantRequest.builder()
                .clientId(registration.getClientId())
                .clientSecret(registration.getClientSecret())
                .code(code)
                .redirectUri(registration.getRedirectUri())
                .build();

        RequestEntity<?> requestEntity = getRequestEntity(registration, request);

        ResponseEntity<AccessTokenResponse> response = this.restTemplate.exchange(requestEntity, AccessTokenResponse.class);

        return response.getBody();
    }



    private RequestEntity<?> getRequestEntity(ClientRegistration registration, AuthorizationRequest request) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        if (registration.getClientAuthenticationMethod().equals(ClientRegistration.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
            headers.set("Authorization", request.getHeader());
        }

        LinkedMultiValueMap<String, String> body = request.getBody();

        return RequestEntity
                .post(registration.getTokenUri())
                .headers(headers)
                .body(body);
    }
}

```

Finally, we got an access token and refresh token in AccessTokenResponse.
Move to step 8 to see how to use the access token to access Tiki services through APIs.

# Step 7: Obtain access token by refresh token
Prerequisites
- You have to get a refresh token that is stored after finishing step 6.

Implement RefreshTokenRequest to specify the request using refresh token (type of auth flow).

```java

@Data
@Builder
public class RefreshTokenRequest implements AuthorizationRequest {
    @JsonProperty("grant_type")
    private final String grantType = "refresh_token";

    private String refreshToken;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("client_secret")
    private String clientSecret;

    @Override
    public LinkedMultiValueMap<String, String> getBody() {
        LinkedMultiValueMap<String, String> result = new LinkedMultiValueMap<>();
        result.put("grant_type", Collections.singletonList(grantType));
        result.put("client_id", Collections.singletonList(clientId));
        result.put("refresh_token", Collections.singletonList(refreshToken));
        result.put("client_secret", Collections.singletonList(clientSecret));
        return result;
    }

    @Override
    public String getHeader() {
        String credentials = clientId + ":" + clientSecret;
        return "Basic " + Base64Utils.encodeToString(credentials.getBytes());
    }
}
```

Next, implement detail the method getAccessTokenByRefreshToken() in the TokenResponseClientImpl class.

```java
package com.example.javaoauth2client.oauth2;

import com.example.javaoauth2client.oauth2.registration.ClientRegistration;
import com.example.javaoauth2client.oauth2.token.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Component
@RequiredArgsConstructor
public class TokenResponseClientImpl implements TokenResponseClient {

    private final RestTemplate restTemplate;

     @Override
    public AccessTokenResponse getAccessTokenByRefreshToken(ClientRegistration registration, String refreshToken) {
        AuthorizationRequest request = RefreshTokenRequest.builder()
                .clientId(registration.getClientId())
                .clientSecret(registration.getClientSecret())
                .refreshToken(refreshToken)
                .build();

        RequestEntity<?> requestEntity = getRequestEntity(registration, request);

        ResponseEntity<AccessTokenResponse> response = this.restTemplate.exchange(requestEntity, AccessTokenResponse.class);

        return response.getBody();
    }



    private RequestEntity<?> getRequestEntity(ClientRegistration registration, AuthorizationRequest request) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        if (registration.getClientAuthenticationMethod().equals(ClientRegistration.ClientAuthenticationMethod.CLIENT_SECRET_BASIC)) {
            headers.set("Authorization", request.getHeader());
        }

        LinkedMultiValueMap<String, String> body = request.getBody();

        return RequestEntity
                .post(registration.getTokenUri())
                .headers(headers)
                .body(body);
    }
}

```

Finally, we got an access token and refresh token in AccessTokenResponse.
Move to step 8 to see how to use the access token to access Tiki services through APIs.

# Step 8: Access Tiki services through APIs
You should have a service to store and retrieve access tokens and refresh tokens by user (current) and client registration's id.

```java 
public interface OAuthTokenService {
    void storeTokens(String appId, String accessToken, String refreshToken);

    String getAccessToken(String appId);

    String getRefreshToken();
}

```

Next, Implement an TikiAPI extends AbstractAccessTokenApi that contains access token

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

    public class TikiApi extends AbstractAccessTokenApi {
        private static final String SELLER_BASE_URL = "https://api.tiki.vn/integration/v2/sellers";

        public TikiApi(String accessToken) {
            super(accessToken);
        }

        public String getSeller() {
            return restTemplate.getForObject(
                    SELLER_BASE_URL + "/me", String.class);
        }
    }
}
```

Define TikiApi beans and their dependency injection in ClientRegistrationConfig file with scope - request

```java
    @Bean
    @RequestScope
    public TikiApi tikiApi(OAuthTokenService oAuthTokenService) {
        String accessToken = oAuthTokenService.getAccessToken("tiki");
        return new TikiApi(accessToken);
    }
```

Test API

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
