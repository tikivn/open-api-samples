package com.example.javaoauth2client.oauth2.token;

import org.springframework.util.LinkedMultiValueMap;

public interface AuthorizationRequest {
    LinkedMultiValueMap<String, String> getBody();
    String getHeader();
}
