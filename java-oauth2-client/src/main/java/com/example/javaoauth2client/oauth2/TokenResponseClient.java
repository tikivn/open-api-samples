package com.example.javaoauth2client.oauth2;

import com.example.javaoauth2client.oauth2.registration.ClientRegistration;
import com.example.javaoauth2client.oauth2.token.AccessTokenResponse;

public interface TokenResponseClient {
    AccessTokenResponse getAccessTokenByAuthorizationCode(ClientRegistration registration, String code);

    AccessTokenResponse getAccessTokenByRefreshToken(ClientRegistration registration, String refreshToken);

    AccessTokenResponse getAccessTokenByClientCredentials(ClientRegistration registration);
}
