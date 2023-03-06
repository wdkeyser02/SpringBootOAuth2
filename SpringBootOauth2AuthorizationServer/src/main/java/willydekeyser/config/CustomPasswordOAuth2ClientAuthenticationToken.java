package willydekeyser.config;

import java.util.Map;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

public class CustomPasswordOAuth2ClientAuthenticationToken extends OAuth2ClientAuthenticationToken {

	private static final long serialVersionUID = 1L;
	
	public CustomPasswordOAuth2ClientAuthenticationToken(String clientId,
			ClientAuthenticationMethod clientAuthenticationMethod, Object credentials,
			Map<String, Object> additionalParameters) {
		super(clientId, clientAuthenticationMethod, credentials, additionalParameters);
	}

	public CustomPasswordOAuth2ClientAuthenticationToken(RegisteredClient registeredClient,
			ClientAuthenticationMethod clientAuthenticationMethod, Object credentials) {
		super(registeredClient, clientAuthenticationMethod, credentials);
	}
}
