package willydekeyser.model;

import java.util.Collection;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import lombok.RequiredArgsConstructor;
import willydekeyser.entity.User;

@RequiredArgsConstructor
public class MyUserDetails implements UserDetails {

	private static final long serialVersionUID = 1L;
	
	private final User user;
	
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return user.getAuthorities().stream()
				.map(auth -> new SimpleGrantedAuthority(auth.getAuthority()))
				.collect(Collectors.toSet());
	}

	@Override
	public String getPassword() {
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		return user.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {
		return user.getAccountNonExpired();
	}

	@Override
	public boolean isAccountNonLocked() {
		return user.getAccountNonLocked();
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return user.getCredentialsNonExpired();
	}

	@Override
	public boolean isEnabled() {
		return user.getEnabled();
	}

}
