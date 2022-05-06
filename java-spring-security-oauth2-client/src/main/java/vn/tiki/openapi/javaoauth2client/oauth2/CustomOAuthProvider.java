package vn.tiki.openapi.javaoauth2client.oauth2;


import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistration.Builder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

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