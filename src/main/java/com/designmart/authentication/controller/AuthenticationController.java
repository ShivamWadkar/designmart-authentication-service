package com.designmart.authentication.controller;

import com.designmart.authentication.entity.User;
import com.designmart.authentication.dto.AuthenticationRequest;
import com.designmart.authentication.security.JwtUtil;
import com.designmart.authentication.service.CustomUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @PostMapping("/login")
    public String login(@RequestBody AuthenticationRequest request) throws Exception {
        try {
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );
        } catch (AuthenticationException e) {
            throw new Exception("Invalid username/password");
        }

        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());
        return jwtUtil.generateToken(userDetails.getUsername());
    }

    @PostMapping("/signup")
    public String signup(@RequestBody User user) {
        // Hash password before saving it
        user.setPassword(new BCryptPasswordEncoder().encode(user.getPassword()));
        // Save user
        user.setRole(user.getRole());
        userDetailsService.save(user);
        return "User registered successfully";
    }
}
