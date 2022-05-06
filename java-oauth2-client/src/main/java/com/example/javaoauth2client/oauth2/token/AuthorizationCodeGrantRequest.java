package com.example.javaoauth2client.oauth2.token;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;
import org.springframework.util.Base64Utils;
import org.springframework.util.LinkedMultiValueMap;

import java.util.Collections;

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
