package willydekeyser.config;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Enumeration;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class LogFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		LocalDateTime date = LocalDateTime.now();
		ContentCachingRequestWrapper requestWrapper = new ContentCachingRequestWrapper(request);
		ContentCachingResponseWrapper responseWrapper = new ContentCachingResponseWrapper(response);
		System.err.println("------------------------------------------------------------------------");
		System.err.println("START LOGFILTER: "  + date + " - " + request.getLocalAddr() + ":" + request.getLocalPort() + request.getServletPath() + "\nRequest:");
		Enumeration<String> headers = request.getHeaderNames();
		while(headers.hasMoreElements()) {
	        String headerName = (String)headers.nextElement();
	        System.out.println("\tHeader: " + headerName + ":" + request.getHeader(headerName));
	    }
		System.out.println("\n");
		Enumeration<String> parameters = request.getParameterNames();
		while(parameters.hasMoreElements()) {
	        String parameterName = (String)parameters.nextElement();
	        System.out.println("\tParameter: " + parameterName + ": " + request.getParameter(parameterName));
	    }
		System.out.println("\n");
		Enumeration<String> attributes = request.getAttributeNames();
		while(attributes.hasMoreElements()) {
	        String attributeName = (String)attributes.nextElement();
	        System.out.println("\tAttribute: " + attributeName + ": " + request.getParameter(attributeName));
	    }
		
		filterChain.doFilter(requestWrapper, responseWrapper);
		
		String requestBody = getStringValue(requestWrapper.getContentAsByteArray(),
				request.getCharacterEncoding());
		String responseBody = getStringValue(responseWrapper.getContentAsByteArray(),
				response.getCharacterEncoding());
		
		System.out.println("Request Body: " + requestBody + "\n");
		System.out.println("Response Body: " + responseBody + "\n");
		System.out.println("\n");
		Collection<String> responseHeaders = response.getHeaderNames();
		responseHeaders.forEach(x -> System.out.println("\tHeader: " + x + ": " + response.getHeader(x)));
		System.out.println("\n\n");
		
		
		System.err.println("END LOG FILTER");
		System.err.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n\n");
		
		responseWrapper.copyBodyToResponse();
	}

	private String getStringValue(byte[] contentAsByteArray, String characterEncoding) {
		try {
			return new String(contentAsByteArray, 0, contentAsByteArray.length, characterEncoding);
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return "";
	}
}
