package willydekeyser.config;

import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;


@HttpExchange("http://localhost:8091")
public interface WelcomeClient2 {

	@GetExchange("/")
	String getWelcome();
	
	
}
