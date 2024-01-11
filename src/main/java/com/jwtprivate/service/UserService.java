package com.jwtprivate.service;

import com.jwtprivate.entities.User;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserService extends UserDetailsService {
    User getUserProfile(String username);
}
