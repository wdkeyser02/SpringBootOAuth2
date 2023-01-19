package willydekeyser.config;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, ClientRegistrationRepository repo) throws Exception {
		
		var base_uri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
	    var resolver = new DefaultOAuth2AuthorizationRequestResolver(repo, base_uri);
	    
	    resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
	    
		http
			.authorizeHttpRequests(authorize -> authorize
					.anyRequest().authenticated())
			.oauth2Login(oauth2Login -> {
				oauth2Login.loginPage("/oauth2/authorization/myoauth2");
				oauth2Login.authorizationEndpoint().authorizationRequestResolver(resolver);})
			.oauth2Client(withDefaults());
		return http.build();
	}
}
