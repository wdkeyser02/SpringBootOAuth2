package willydekeyser.config;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Enumeration;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

//@Component
//@Order(Ordered.HIGHEST_PRECEDENCE)
public class LogFilter implements Filter {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		LocalDateTime date = LocalDateTime.now();
		System.err.println("LogFilter: " + date + " - " + httpRequest.getLocalAddr() + ":" + httpRequest.getLocalPort() + httpRequest.getServletPath());
		System.out.println("Request:");
		Enumeration<String> headers = httpRequest.getHeaderNames();
		while(headers.hasMoreElements()) {
	        String headerName = (String)headers.nextElement();
	        System.out.println("\tHeader: " + headerName + ":" + httpRequest.getHeader(headerName));
	    }
		System.out.println("\n");
		Enumeration<String> parameters = httpRequest.getParameterNames();
		while(parameters.hasMoreElements()) {
	        String parameterName = (String)parameters.nextElement();
	        System.out.println("\tParameter: " + parameterName + ": " + httpRequest.getParameter(parameterName));
	    }
		System.out.println("\nResponse:");
		chain.doFilter(request, response);
		Collection<String> responseHeaders = httpResponse.getHeaderNames();
		responseHeaders.forEach(x -> System.out.println("\tHeader: " + x + ": " + httpResponse.getHeader(x)));
		System.out.println("\n\n");
	}

}