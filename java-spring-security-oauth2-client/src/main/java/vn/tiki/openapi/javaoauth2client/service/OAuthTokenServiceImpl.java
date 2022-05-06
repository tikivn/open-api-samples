package vn.tiki.openapi.javaoauth2client.service;

import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Service;

@Service
public class OAuthTokenServiceImpl implements OAuthTokenService {
    @Override
    public void storeTokens(String appId, OAuth2AccessToken accessToken, OAuth2RefreshToken refreshToken) {

    }

    @Override
    public String getAccessToken(String appId) {
        return "QsUuf6YtidFi1bmhBwjvfJyZfq7pI-QqLrpJXAQ20gY.pRcvfaWCz7Faph5VOBqcREWOdV_xxx";
    }

    @Override
    public String getRefreshToken() {
        return "sHjPiRaa_LviKN6xfOa2lFw2JWnonJIeA1VN_FHcoQ8.FSlIuMxHTYiROtqQukhxRYx1X3WSq6-xxxx";
    }
}
