package willydekeyser.config;


import static java.util.Objects.isNull;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Component;

@Component
public class OAuth2ClientInterceptor implements ClientHttpRequestInterceptor {

	private final OAuth2AuthorizedClientManager manager;
    private final ClientRegistration clientRegistration;

    public OAuth2ClientInterceptor(OAuth2AuthorizedClientManager manager,  ClientRegistrationRepository clientRegistrationRepository) {
        this.manager = manager;
        this.clientRegistration = clientRegistrationRepository.findByRegistrationId("myoauth2");
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        
    	Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    	OAuth2AuthorizeRequest oAuth2AuthorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId(clientRegistration.getRegistrationId())
                .principal(authentication)
                .build();

        OAuth2AuthorizedClient client = manager.authorize(oAuth2AuthorizeRequest);
        if (isNull(client)) {
            throw new IllegalStateException("Missing credentials");
        }

        System.err.println("\n\nTOKEN: " + client.getAccessToken().getTokenValue());
        System.out.println("\n\n\n");
        
        request.getHeaders().add(HttpHeaders.AUTHORIZATION,
                "Bearer " + client.getAccessToken().getTokenValue());

        return execution.execute(request, body);
    }

}
