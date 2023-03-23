package willydekeyser.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class WelcomeController {
	
	@Autowired
    RestTemplateBuilder restTemplateBuilderConfigured;
	
	@GetMapping("/")
	public String welcome() {
		RestTemplate restTemplate = restTemplateBuilderConfigured.build();
		String welcome = restTemplate.getForEntity("/", String.class).getBody();	
		return "<h1>" +  welcome + "</h1>";
	}
}
