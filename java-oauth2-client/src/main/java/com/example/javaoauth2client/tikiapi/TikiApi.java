package com.example.javaoauth2client.tikiapi;

public class TikiApi extends AbstractAccessTokenApi {
    private static final String SELLER_BASE_URL = "https://api.tiki.vn/integration/v2/sellers";

    public TikiApi(String accessToken) {
        super(accessToken);
    }

    public String getSeller() {
        return restTemplate.getForObject(
                SELLER_BASE_URL + "/me", String.class);
    }
}
