package willydekeyser.config;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

public class CustomPassordAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
	private final OAuth2AuthorizationService authorizationService;
	private final UserDetailsService userDetailsService;
	private final JWKSource<SecurityContext> jwkSource;
	private String username = "";
	private String password = "";
	private Set<String> authorizedScopes = new HashSet<>();

	public CustomPassordAuthenticationProvider(OAuth2AuthorizationService authorizationService,
			JWKSource<SecurityContext> jwkSource, 
			UserDetailsService userDetailsService) {
		
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(jwkSource, "jwkSource cannot be null");
		this.authorizationService = authorizationService;
		this.jwkSource = jwkSource;
		this.userDetailsService = userDetailsService;
	}
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		
		CustomPasswordAuthenticationToken customPasswordAuthenticationToken = (CustomPasswordAuthenticationToken) authentication;
		OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(customPasswordAuthenticationToken);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
		//OAuth2Authorization authorization = this.authorizationService.findById(registeredClient.getClientId());
		username = customPasswordAuthenticationToken.getUsername();
		password = customPasswordAuthenticationToken.getPassword();
				
		User user = null;
		try {
			user = (User) userDetailsService.loadUserByUsername(username);
		} catch (UsernameNotFoundException e) {
			System.err.println(e.getMessage());
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
		}
		if (!user.getPassword().equals(password) || ! user.getUsername().equals(username)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
		}
		authorizedScopes = user.getAuthorities().stream()
				.map(scope -> scope.getAuthority())
				.filter(scope -> registeredClient.getScopes().contains(scope))
				.collect(Collectors.toSet());
				
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
				.registeredClient(registeredClient)
				.principal(clientPrincipal)
				.authorizationServerContext(AuthorizationServerContextHolder.getContext())
				.authorizedScopes(authorizedScopes)
				.authorizationGrantType(new AuthorizationGrantType("custom_password"))
				.authorizationGrant(customPasswordAuthenticationToken);
		
		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
				.attribute(Principal.class.getName(), clientPrincipal)
				.principalName(clientPrincipal.getName())
				.authorizationGrantType(new AuthorizationGrantType("custom_password"))
				.authorizedScopes(authorizedScopes);
		
		//-----------ACCESS TOKEN----------
		OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
		OAuth2Token generatedAccessToken = tokenGenerator().generate(tokenContext);
		if (generatedAccessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the access token.", ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
				generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
		if (generatedAccessToken instanceof ClaimAccessor) {
			authorizationBuilder.token(accessToken, (metadata) ->
					metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generatedAccessToken).getClaims()));
		} else {
			authorizationBuilder.accessToken(accessToken);
		}
		
		//-----------REFRESH TOKEN----------
		OAuth2RefreshToken refreshToken = null;
		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
				!clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {

			tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
			OAuth2Token generatedRefreshToken = tokenGenerator().generate(tokenContext);
			if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
						"The token generator failed to generate the refresh token.", ERROR_URI);
				throw new OAuth2AuthenticationException(error);
			}
			refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
			authorizationBuilder.refreshToken(refreshToken);
		}
				
		OAuth2Authorization authorization = authorizationBuilder
				//.principalName(clientPrincipal.getName())
				//.authorizationGrantType(new AuthorizationGrantType("custom_password"))
				.build();
		this.authorizationService.save(authorization);
		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken, refreshToken);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return CustomPasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
		OAuth2ClientAuthenticationToken clientPrincipal = null;
		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
		}
		if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
			return clientPrincipal;
		}
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}
	
	private OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator() {
		NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(this.jwkSource);
		JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
		jwtGenerator.setJwtCustomizer(tokenCustomizer());
		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
		OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
		return new DelegatingOAuth2TokenGenerator(
				jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
	}
	
	private OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
		return context -> {
			if (context.getTokenType().getValue().equals("access_token")) {
                context.getClaims().claim("authorities", authorizedScopes)
                        .claim("user", username);
			}
		};
	}
}
