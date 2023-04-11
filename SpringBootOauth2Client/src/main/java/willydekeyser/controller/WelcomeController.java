package willydekeyser.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import willydekeyser.config.WelcomeClient;

@RestController
@RequiredArgsConstructor
public class WelcomeController {
	
	private final WelcomeClient welcomeClient;
	
	@GetMapping("/")
	public String welcome() {
		
		String welcomeFirst = welcomeClient.getWelcomeFirst();		
		String welcomeSecond = welcomeClient.getWelcomeSecond();	
		return "<h1>" +  welcomeFirst + "</h1><h1>" +  welcomeSecond + "</h1>";
	}
	
}
