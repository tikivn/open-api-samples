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
