package vn.tiki.openapi.javaoauth2client.controller;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import lombok.RequiredArgsConstructor;
import org.springframework.core.ResolvableType;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import vn.tiki.openapi.javaoauth2client.service.OAuthTokenService;

@Controller
@RequiredArgsConstructor
public class OAuthController {

    private static final String authorizationRequestBaseUri = "/oauth2/authorize-client";

    private final ClientRegistrationRepository clientRegistrationRepository;

    private final OAuth2AuthorizedClientService authorizedClientService;

    private final OAuthTokenService oAuthTokenService;

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

    @GetMapping("/oauth/authorized")
    public String handleSuccessLogin(OAuth2AuthenticationToken oAuth2AuthenticationToken) {
        String appId = oAuth2AuthenticationToken.getAuthorizedClientRegistrationId();
        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                appId, oAuth2AuthenticationToken.getName());
        OAuth2AccessToken accessToken = Objects.requireNonNull(authorizedClient).getAccessToken();
        OAuth2RefreshToken refreshToken = Objects.requireNonNull(authorizedClient).getRefreshToken();
        oAuthTokenService.storeTokens(appId, accessToken, refreshToken);

        return "index";
    }
}