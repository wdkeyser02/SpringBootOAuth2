package willydekeyser.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import willydekeyser.config.WelcomeClient;
import willydekeyser.config.WelcomeClient2;


@RestController
@RequiredArgsConstructor
public class WelcomeController {
	
	private final WelcomeClient welcomeClient;
	private final WelcomeClient2 welcomeClient2;
	
	@GetMapping("/")
	public String index(Authentication authentication) {
		String welcome = welcomeClient.getWelcome();
		String welcome2 = welcomeClient2.getWelcome();
		return "<h1> Welcome: " + authentication.getName() + "</h1><h2>" + welcome + "</h2><h2>" + welcome2 + "</h2>";
	}
		
}
