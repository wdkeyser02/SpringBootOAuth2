package willydekeyser.config;

import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.HttpExchange;


@HttpExchange("http://localhost:9999")
public interface WelcomeClient {

	@GetExchange("/first")
	String getWelcomeFirst();
	
	@GetExchange("/second")
	String getWelcomeSecond();
}
