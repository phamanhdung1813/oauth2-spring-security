package com.anhdungpham.auth;

import com.anhdungpham.auth.impl.IUserSecurityDAO;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Repository("user_security_repository")
@RequiredArgsConstructor
public class UserSecurityDAO implements IUserSecurityDAO {
    private final PasswordEncoder passwordEncoder;

    private List<CustomUserDetails> customUserDetailsList() {
        Set<SimpleGrantedAuthority> grantedAuthorities = new HashSet<>();
        grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        grantedAuthorities.add(new SimpleGrantedAuthority("read"));
        grantedAuthorities.add(new SimpleGrantedAuthority("write"));

        return List.of(
                new CustomUserDetails("admin", passwordEncoder.encode("admin"),
                        grantedAuthorities, true, true,
                        true, true)
        );
    }

    @Override
    public Optional<CustomUserDetails> findByUsername(String username) {
        return customUserDetailsList().stream()
                .filter(user -> username.equals(user.getUsername())).findFirst();
    }
}
