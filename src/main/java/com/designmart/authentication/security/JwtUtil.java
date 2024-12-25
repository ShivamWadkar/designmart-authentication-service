package com.designmart.authentication.security;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey; // JWT secret key

    @Value("${jwt.expiration}")
    private long jwtExpiration; // JWT expiration time in milliseconds

    // Generate JWT Token
    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
                .signWith(SignatureAlgorithm.HS256, secretKey.getBytes(StandardCharsets.UTF_8))
                .compact();
    }

    // Extract username from JWT Token
    public String extractUsername(String token) {
        return extractClaims(token).getSubject();
    }

    // Extract claims from JWT Token
    private Claims extractClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secretKey.getBytes(StandardCharsets.UTF_8))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // Validate JWT Token
    public boolean isTokenExpired(String token) {
        return extractClaims(token).getExpiration().before(new Date());
    }

    // Validate JWT Token
    public boolean validateToken(String token, String username) {
        return (username.equals(extractUsername(token)) && !isTokenExpired(token));
    }
}
