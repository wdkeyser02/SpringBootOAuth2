package willydekeyser.config;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import org.springframework.util.Assert;

public class CustomPasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {

	private static final long serialVersionUID = 1L;
	private final String username;
	private final String password;
	private final Set<String> scopes;
	
	public CustomPasswordAuthenticationToken(String username, String password, Authentication clientPrincipal,
			@Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
		super(new AuthorizationGrantType("custom_password"), clientPrincipal, additionalParameters);
		Assert.hasText(username, "assertion cannot be empty");
		this.username = username;
		this.password = password;
		this.scopes = Collections.unmodifiableSet(
				scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
	}

	public String getUsername() {
		return this.username;
	}
	
	public String getPassword() {
		return this.password;
	}

	public Set<String> getScopes() {
		return this.scopes;
	}
}
