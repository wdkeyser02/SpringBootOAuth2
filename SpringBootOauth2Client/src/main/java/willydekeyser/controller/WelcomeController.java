package willydekeyser.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import willydekeyser.config.WelcomeClient;

@RestController
@RequiredArgsConstructor
public class WelcomeController {
	
	private final WelcomeClient welcomeClient;
	private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;
	
	@GetMapping("/")
	public String welcome(Authentication authentication) {
		
		OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
		OAuth2AuthorizedClient oAuth2AuthorizedClient = oAuth2AuthorizedClientService.loadAuthorizedClient(oAuth2AuthenticationToken.getAuthorizedClientRegistrationId(), oAuth2AuthenticationToken.getName());
		String jwtAccessToken = oAuth2AuthorizedClient.getAccessToken().getTokenValue();
		
		String welcome = "";
		Map<String, String> headers = new HashMap<>();
		headers.put("authorization", "Bearer " + jwtAccessToken);
		try {
			welcome = welcomeClient.getWelcome(headers);			
		} catch (Exception e) {
			welcome = e.getMessage();
		}
		return "<h1>" +  welcome + "</h1>";
	}
	
}
