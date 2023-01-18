package willydekeyser.config;

import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;


@HttpExchange("http://localhost:8090")
public interface WelcomeClient {

	@GetExchange("/")
	String getWelcome();
	
	
}
