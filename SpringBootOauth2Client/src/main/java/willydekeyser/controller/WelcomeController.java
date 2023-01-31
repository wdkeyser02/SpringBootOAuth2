package willydekeyser.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;


@RestController
@RequiredArgsConstructor
public class WelcomeController {
	
	//private final WelcomeClient welcomeClient;
	
	@GetMapping("/")
	public String index() {
		
		//String welcome = welcomeClient.getWelcome();			
		//return "<h1>" +  welcome + "</h1>";
		return "<h1> Login! </h1><p><a href ='/oauth2/authorization/myoauth2server1'>Server 1</a></p><p><a href = '/oauth2/authorization/myoauth2server2'>Server 2</a></p>";
	}
	
	@GetMapping("/welcome")
	public String welcome(Authentication authentication) {
		
		//String welcome = welcomeClient.getWelcome();			
		//return "<h1>" +  welcome + "</h1>";
		return "<h1> Welcome! </h1><h2>" + authentication.getName() + "</h2>";
	}
	
}
