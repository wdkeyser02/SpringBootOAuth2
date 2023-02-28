package willydekeyser;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class JwtBearerGrantTests {
	
	private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";
	private static final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
			new OAuth2AccessTokenResponseHttpMessageConverter();

	@Autowired
	private MockMvc mvc;

	@Test
	public void exchangeAccessTokenUsingJwtBearerGrant() throws Exception {
		
		System.err.println("\nStart JwtBearerGrantTests\n");
		
		// Obtain access token using 'client_credentials' grant
		MvcResult mvcResult = this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.param(OAuth2ParameterNames.SCOPE, "message.read message.write")
				.header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
						"client", "secret")))
				.andExpect(status().isOk())
				.andReturn();

		String accessToken = getAccessToken(mvcResult).getTokenValue();
		System.err.println("\nAccess token from 'client_credentials' grant -> " + accessToken);

		// Exchange access token using 'jwt-bearer' grant
		mvcResult = this.mvc.perform(post(DEFAULT_TOKEN_ENDPOINT_URI)
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.JWT_BEARER.getValue())
				.param(OAuth2ParameterNames.ASSERTION, accessToken)
				.param(OAuth2ParameterNames.SCOPE, "message.read")
				.header(HttpHeaders.AUTHORIZATION, "Basic " + encodeBasicAuth(
						"client", "secret")))
				.andExpect(status().isOk())
				.andReturn();

		accessToken = getAccessToken(mvcResult).getTokenValue();
		System.err.println("\nAccess token from 'jwt-bearer' grant -> " + accessToken);
			
		System.err.println("\nEnd JwtBearerGrantTests");
	}

	private static OAuth2AccessToken getAccessToken(MvcResult mvcResult) {
		MockHttpServletResponse servletResponse = mvcResult.getResponse();
		MockClientHttpResponse httpResponse = new MockClientHttpResponse(
				servletResponse.getContentAsByteArray(), HttpStatus.valueOf(servletResponse.getStatus()));
		try {
			return accessTokenHttpResponseConverter.read(
					OAuth2AccessTokenResponse.class, httpResponse).getAccessToken();
		} catch (Exception ex) {
			System.err.println("FOUT " + ex.getMessage());
			throw new RuntimeException(ex);
		}
	}

	private static String encodeBasicAuth(String clientId, String secret) throws Exception {
		clientId = URLEncoder.encode(clientId, StandardCharsets.UTF_8.name());
		secret = URLEncoder.encode(secret, StandardCharsets.UTF_8.name());
		String credentialsString = clientId + ":" + secret;
		byte[] encodedBytes = Base64.getEncoder().encode(credentialsString.getBytes(StandardCharsets.UTF_8));
		return new String(encodedBytes, StandardCharsets.UTF_8);
	}

}