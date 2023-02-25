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

public class JwtBearerGrantAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
	
	private static final long serialVersionUID = 1L;
	private final String assertion;
	private final Set<String> scopes;

	public JwtBearerGrantAuthenticationToken(String assertion, Authentication clientPrincipal,
			@Nullable Set<String> scopes, @Nullable Map<String, Object> additionalParameters) {
		super(AuthorizationGrantType.JWT_BEARER, clientPrincipal, additionalParameters);
		Assert.hasText(assertion, "assertion cannot be empty");
		this.assertion = assertion;
		this.scopes = Collections.unmodifiableSet(
				scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
	}

	public String getAssertion() {
		return this.assertion;
	}

	public Set<String> getScopes() {
		return this.scopes;
	}

}