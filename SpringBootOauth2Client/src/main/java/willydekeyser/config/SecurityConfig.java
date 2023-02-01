package willydekeyser.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorize -> authorize
					.requestMatchers("/login").permitAll()
					.anyRequest().authenticated())
			.oauth2Login(login -> login
					.loginPage("/login")
					.defaultSuccessUrl("/welcome")
			)
			.oauth2Client(withDefaults());
		return http.build();
	}
}
