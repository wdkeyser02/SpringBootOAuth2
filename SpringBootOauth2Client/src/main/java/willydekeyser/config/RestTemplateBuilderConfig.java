package willydekeyser.config;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.web.client.RestTemplateBuilderConfigurer;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.web.util.DefaultUriBuilderFactory;

@Configuration
public class RestTemplateBuilderConfig {

	@Value("http://localhost:8090")
	String resourceServerUrl;
	
	@Bean
    public RestTemplateBuilder restTemplateBuilder(RestTemplateBuilderConfigurer configurer,
                                            OAuth2ClientInterceptor interceptor){

        assert resourceServerUrl != null;

        return configurer.configure(new RestTemplateBuilder())
                .additionalInterceptors(interceptor)
                .uriTemplateHandler(new DefaultUriBuilderFactory(resourceServerUrl));
    }
	
	@Bean
	public OAuth2AuthorizedClientManager authorizedClientManager(
	        ClientRegistrationRepository clientRegistrationRepository,
	        OAuth2AuthorizedClientRepository authorizedClientRepository) {
	    
	    OAuth2AuthorizedClientProvider authorizedClientProvider = 
	            OAuth2AuthorizedClientProviderBuilder.builder()
	            .authorizationCode()
	            .refreshToken()
	            .build();
	    
	    DefaultOAuth2AuthorizedClientManager authorizedClientManager =
	            new DefaultOAuth2AuthorizedClientManager(
	                    clientRegistrationRepository, authorizedClientRepository);
	   
	    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

	    return authorizedClientManager;
	}

}
