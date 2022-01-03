package com.anhdungpham.auth.impl;

import com.anhdungpham.auth.CustomUserDetails;

import java.util.Optional;

public interface IUserSecurityDAO {
    Optional<CustomUserDetails> findByUsername(String username);
}
