package willydekeyser.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import willydekeyser.config.WelcomeClient;


@RestController
@RequiredArgsConstructor
public class WelcomeController {
	
	private final WelcomeClient welcomeClient;
	
	@GetMapping("/")
	public String index(Authentication authentication) {
		String welcome = welcomeClient.getWelcome();
		return "<h1> Welcome: " + authentication.getName() + "</h1><h2>" + welcome + "</h2>";
	}
		
}
