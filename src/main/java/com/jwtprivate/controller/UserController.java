package com.jwtprivate.controller;

import com.jwtprivate.entities.AuthRequest;
import com.jwtprivate.entities.AuthResponse;
import com.jwtprivate.entities.User;
import com.jwtprivate.service.JwtService;
import com.jwtprivate.service.UserServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class UserController {
    @Autowired
    private UserServiceImpl service;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @GetMapping("/welcome")
    public String welcome() {
        return "Welcome this endpoint is not secure";
    }

    @PostMapping("/addNewUser")
    public String addNewUser(@RequestBody User user) {
        return service.addUser(user);
    }

    @GetMapping("/user/userProfile")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public User userProfile(HttpServletRequest request) {
        String username = jwtService.getUserNameFromRequest(request);
        return service.getUserProfile(username);
    }

    @GetMapping("/admin/adminProfile")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public User adminProfile(HttpServletRequest request) {
        String username = jwtService.getUserNameFromRequest(request);
        return service.getUserProfile(username);
    }

    @PostMapping("/generateToken")
    public AuthResponse authenticateAndGetToken(@RequestBody AuthRequest authRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        if (authentication.isAuthenticated()) {
            return new AuthResponse(jwtService.generateToken(authRequest.getUsername()));
        } else {
            throw new UsernameNotFoundException("invalid user request !");
        }
    }
}
