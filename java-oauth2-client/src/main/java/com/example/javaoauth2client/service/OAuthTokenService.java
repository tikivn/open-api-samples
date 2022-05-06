package com.example.javaoauth2client.service;

public interface OAuthTokenService {
    void storeTokens(String appId, String accessToken, String refreshToken);

    String getAccessToken(String appId);

    String getRefreshToken();
}
