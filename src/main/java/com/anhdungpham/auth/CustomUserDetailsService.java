package com.anhdungpham.auth;

import com.anhdungpham.auth.impl.IUserSecurityDAO;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final IUserSecurityDAO iUserSecurityDAO;

    public CustomUserDetailsService(@Qualifier("user_security_repository") IUserSecurityDAO iUserSecurityDAO) {
        this.iUserSecurityDAO = iUserSecurityDAO;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return iUserSecurityDAO.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(String.format("NOT FOUND USERNAME %s ", username)));
    }
}
