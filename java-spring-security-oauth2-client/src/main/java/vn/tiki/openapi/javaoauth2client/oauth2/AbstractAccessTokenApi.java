package vn.tiki.openapi.javaoauth2client.oauth2;

import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.web.client.RestTemplate;


public abstract class AbstractAccessTokenApi {
    protected RestTemplate restTemplate;

    public AbstractAccessTokenApi(String accessToken) {
        this.restTemplate = new RestTemplate();
        if (accessToken != null) {
            this.restTemplate.getInterceptors()
                    .add(getBearerTokenInterceptor(accessToken));
        } else {
            this.restTemplate.getInterceptors().add(getNoTokenInterceptor());
        }
    }

    private ClientHttpRequestInterceptor getBearerTokenInterceptor(String accessToken) {
        ClientHttpRequestInterceptor interceptor = (request, bytes, execution) -> {
            request.getHeaders().add("Authorization", "Bearer " + accessToken);
            return execution.execute(request, bytes);
        };
        return interceptor;
    }

    private ClientHttpRequestInterceptor getNoTokenInterceptor() {
        return (request, bytes, execution) -> {
            throw new IllegalStateException(
                    "Can't access the API without an access token");
        };
    }
}
