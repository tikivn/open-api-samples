package vn.tiki.openapi.javaoauth2client.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import vn.tiki.openapi.javaoauth2client.oauth2.TikiApi;

@RequiredArgsConstructor
@RestController
public class SellerController {
    private final TikiApi tikiApi;

    @GetMapping("/seller")
    public String getSeller() {
        String seller = tikiApi.getSeller();
        return seller;
    }

}