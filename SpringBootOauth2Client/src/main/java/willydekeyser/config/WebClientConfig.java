package willydekeyser.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.support.WebClientAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
public class WebClientConfig {

	//private final ClientRegistrationRepository clientRegistrationRepository;
	//private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;
	
	@Bean
	public WelcomeClient welcomeClient() throws Exception {
		return httpServiceProxyFactory().createClient(WelcomeClient.class);
	}
	
	private HttpServiceProxyFactory httpServiceProxyFactory() {
		//ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 = new ServletOAuth2AuthorizedClientExchangeFilterFunction(
		//		clientRegistrationRepository, oAuth2AuthorizedClientRepository);
		//oauth2.setDefaultOAuth2AuthorizedClient(true);
		WebClient webClient = WebClient.builder()
		//		.apply(oauth2.oauth2Configuration())			
				.build();
		WebClientAdapter client = WebClientAdapter.forClient(webClient);
		return HttpServiceProxyFactory.builder(client).build();
	}
}
