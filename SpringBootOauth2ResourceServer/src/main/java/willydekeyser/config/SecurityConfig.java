package willydekeyser.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

	@Value("${spring.security.oauth2.resourceserver.opaque.issuer-uri}")
	String issuerUri;
	
	@Value("${spring.security.oauth2.resourceserver.opaque.client}")
	String client;
	
	@Value("${spring.security.oauth2.resourceserver.opaque.secret}")
	String secret;

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http
				.authorizeHttpRequests(auth -> auth
						.anyRequest().authenticated())
				.oauth2ResourceServer(oauth2 -> oauth2
						.opaqueToken()
						.introspectionUri(issuerUri)
						.introspectionClientCredentials(client, secret)
						)
				.build();
	}
}
