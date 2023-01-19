package willydekeyser.config;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Enumeration;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class LogFilter implements Filter {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		HttpServletRequest httpRequest = (HttpServletRequest) request;
		//HttpServletResponse httpResponse = (HttpServletResponse) response;
		LocalDateTime date = LocalDateTime.now();
		System.err.println("LogFilter: " + date + " - " + httpRequest.getLocalAddr() + ":" + httpRequest.getLocalPort() + httpRequest.getServletPath());
		Enumeration<String> headers = httpRequest.getHeaderNames();
		while(headers.hasMoreElements()) {
	        String headerName = (String)headers.nextElement();
	        System.out.println("\tHeader: " + headerName + ":" + httpRequest.getHeader(headerName));
	    }
		System.out.println("\n\n");
		chain.doFilter(request, response);
		
	}

}
