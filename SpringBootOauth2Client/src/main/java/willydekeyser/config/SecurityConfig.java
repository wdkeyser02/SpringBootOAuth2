package willydekeyser.config;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

@Configuration
public class SecurityConfig {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http, ClientRegistrationRepository clientRegistrationRepository) throws Exception {
		
		String base_uri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
	    DefaultOAuth2AuthorizationRequestResolver resolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, base_uri);
	    resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
	    
		http
			.authorizeHttpRequests(authorize -> authorize
					.anyRequest().authenticated())
			.oauth2Login(oauth2Login -> {
				oauth2Login.loginPage("/oauth2/authorization/myoauth2");
				oauth2Login.authorizationEndpoint().authorizationRequestResolver(resolver);
				oauth2Login.userInfoEndpoint(userInfo -> userInfo
						.oidcUserService(this.oidcUserService()));
			})
			.oauth2Client(withDefaults());
		return http.build();
	}
	
	@SuppressWarnings("unchecked")
	//@Bean
	GrantedAuthoritiesMapper userAuthoritiesMapper() {
		return (authorities) -> {
			Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
			authorities.forEach(authority -> {
				if (OidcUserAuthority.class.isInstance(authority)) {
					OidcUserAuthority oidcUserAuthority = (OidcUserAuthority)authority;
					OidcIdToken idToken = oidcUserAuthority.getIdToken();
					if (idToken.hasClaim("authorities")) {
						Collection<String> userAuthorities = (Collection<String>) idToken.getClaim("authorities");
						mappedAuthorities.addAll(userAuthorities.stream()
										.map(SimpleGrantedAuthority::new)
										.toList());
					}
				}
			});
			return mappedAuthorities;
		};
	}
	
	@SuppressWarnings("unchecked")
	private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
		final OidcUserService delegate = new OidcUserService();

		return (userRequest) -> {
			OidcUser oidcUser = delegate.loadUser(userRequest);
			OAuth2AccessToken accessToken = userRequest.getAccessToken();
			//OidcIdToken idToken = userRequest.getIdToken();
			Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
			try {
				JWT jwt = JWTParser.parse(accessToken.getTokenValue());
				Collection<String> claims = (Collection<String>) jwt.getJWTClaimsSet().toJSONObject().get("authorities");
				mappedAuthorities.addAll(claims.stream()
						.map(SimpleGrantedAuthority::new)
						.toList());         
			} catch (Exception e) {
				e.printStackTrace();
			}
			oidcUser = new DefaultOidcUser(mappedAuthorities, oidcUser.getIdToken(), oidcUser.getUserInfo());
			return oidcUser;
		};
	}
}
