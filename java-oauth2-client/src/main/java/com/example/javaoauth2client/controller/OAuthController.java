package com.example.javaoauth2client.controller;

import com.example.javaoauth2client.oauth2.TokenResponseClient;
import com.example.javaoauth2client.oauth2.registration.ClientRegistration;
import com.example.javaoauth2client.oauth2.registration.ClientRegistrationRepository;
import com.example.javaoauth2client.oauth2.token.AccessTokenResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ResolvableType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

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

    @GetMapping("/callback")
    public ResponseEntity<AccessTokenResponse> callback(@RequestParam("code") Optional<String> code,
                                           @RequestParam("error") Optional<String> error,
                                           @RequestParam("error_code") Optional<Integer> errorCode) {

        if (!code.isPresent()) {
            // handle error
        }

        ClientRegistration registration = clientRegistrationRepository.findByRegistrationId("tiki");
        AccessTokenResponse accessToken = tokenResponseClient.getAccessTokenByAuthorizationCode(registration, code.get());


        // call to refresh token
        AccessTokenResponse accessToken2 = tokenResponseClient.getAccessTokenByRefreshToken(registration, accessToken.getRefreshToken());

        return ResponseEntity.ok(accessToken);
    }
}
