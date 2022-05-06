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