package com.jwtprivate.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

@Component
public class JwtService {
    @Value("${jwt.expirationMs}")
    private long expirationMs;

    @Value("${path.to.public-key}")
    private String publicKeyPath;

    @Value("${path.to.private-key}")
    private String privateKeyPath;

    @Autowired
    private KeyReader keyReader;

    public String generateToken(String username) {
        try {
            PrivateKey privateKey = keyReader.getPrivateKey(privateKeyPath);
            Date now = new Date();
            Date expiryDate = new Date(now.getTime() + expirationMs);

            return Jwts.builder()
                    .setSubject(username)
                    .setIssuedAt(now)
                    .setExpiration(expiryDate)
                    .signWith(privateKey, SignatureAlgorithm.RS256)
                    .compact();
        } catch (Exception e) {
            return "";
        }
    }

    public String getUsernameFromToken(String token) {
        try {
            PublicKey publicKey = keyReader.getPublicKey(publicKeyPath);
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(publicKey)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return claims.getSubject();
        } catch (Exception e) {
            return "";
        }
    }

    public boolean validateToken(String token) {
        try {
            PublicKey publicKey = keyReader.getPublicKey(publicKeyPath);
            Jwts.parser().setSigningKey(publicKey).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String getUserNameFromRequest(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        String username = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            username = getUsernameFromToken(authHeader.substring(7));
        }
        return username;
    }
}
