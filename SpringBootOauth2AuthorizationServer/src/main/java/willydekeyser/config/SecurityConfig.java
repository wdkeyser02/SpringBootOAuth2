package willydekeyser.config;

import static org.springframework.security.config.Customizer.withDefaults;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
public class SecurityConfig {

	@Bean
	@Order(1)
	public SecurityFilterChain asSecurityFilterChain(HttpSecurity http) throws Exception {
		
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		return http
				.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(withDefaults())
				.and()
				.exceptionHandling(e -> e
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
				.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
				.build();

	}

	@Bean
	@Order(2)
	public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
		return http
				.formLogin(withDefaults())
				.authorizeHttpRequests(authorize ->authorize.anyRequest().authenticated())
				.build();
		
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client")
				.clientSecret(passwordEncoder().encode("secret"))
				.scope("read")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/myoauth2")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.clientSettings(clientSettings())
				.build();

		return new InMemoryRegisteredClientRepository(registeredClient);
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}
		
	@Bean
	ClientSettings clientSettings() {
		return ClientSettings.builder()
				.requireProofKey(true)
				.build();
	}
	
	@Bean
	OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
		return context -> {
			Authentication principal = context.getPrincipal();
			if (context.getTokenType().getValue().equals("id_token")) {
				context.getClaims().claim("Test", "Test Id Token");
			}
			if (context.getTokenType().getValue().equals("access_token")) {
				context.getClaims().claim("Test", "Test Access Token");
				Set<String> authorities = principal.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
                context.getClaims().claim("authorities", authorities)
                        .claim("user", principal.getName());
			}
			
		};
	}
	
	@Bean 
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}
	
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	public static RSAKey generateRsa() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
	}

	static KeyPair generateRsaKey() {
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}
}
