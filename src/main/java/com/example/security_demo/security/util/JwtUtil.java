package com.example.security_demo.security.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Date;
import java.util.List;

@Component
public class JwtUtil {

    private final String SECRET = "fa04ba3741c723e9509224985307f1837da2186aca4c92e4931c854ddf711b5e";
    private final long EXP_TIME = 86400000;

    public String generateToken(UserDetails userDetails) {
        return Jwts
                .builder()
                .setSubject(userDetails.getUsername()) // subject -> to whom the token is issued
                .claim("roles", getUserRoles(userDetails.getAuthorities()))
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXP_TIME)) // expiring at current time + 1 day
                .signWith(SignatureAlgorithm.HS256, SECRET)
                .compact();
    }

    private List<String> getUserRoles(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream().map(GrantedAuthority::getAuthority).toList();
    }

    public String extractUserName(String token) {
        return getBody(token).getSubject();
    }

    private Claims getBody(String token) {
        return Jwts.parser().setSigningKey(SECRET).parseClaimsJws(token).getBody();
    }

    public List<String> extractRoles(String token) {
        return getBody(token).get("roles", List.class);
    }

    public boolean validateToken(String token, UserDetails userDetails) {
        return extractUserName(token).equals(userDetails.getUsername())
                && !isTokenExpired(token);
    }

    public boolean isTokenExpired(String token) {
        return getBody(token).getExpiration().before(new Date());
    }
}
