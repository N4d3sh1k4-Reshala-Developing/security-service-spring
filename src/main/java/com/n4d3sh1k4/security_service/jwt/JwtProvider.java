package com.n4d3sh1k4.security_service.jwt;

import com.n4d3sh1k4.security_service.domain.model.users.User;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Slf4j
@Component
public class JwtProvider {

    private final SecretKey jwtAccessSecret;

    public JwtProvider(@Value("${jwt.secret.access}") String jwtAccessSecret) {
        this.jwtAccessSecret = Keys.hmacShaKeyFor(Decoders.BASE64.decode((jwtAccessSecret)));
    }

    //Оставить
    public String generateAccessToken(@NonNull User user) {
        return Jwts.builder()
                .subject(user.getUsername())
                .claim("roles", user.getRoles().stream().map(r -> "ROLE_" + r.getName()).toList())
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plus(15, ChronoUnit.MINUTES)))
                .signWith(jwtAccessSecret)
                .compact();
    }

    public boolean validateAccessToken(@NonNull String token) {
        return validateToken(token, jwtAccessSecret);
    }

    public Claims getAccessClaims(@NonNull String token) {return getClaims(token, jwtAccessSecret);}

    //Вспомогательные методы
    private boolean  validateToken(@NonNull String token, @NonNull SecretKey key) {
        try {
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            log.error("Invalid JWT token: {}", e.getMessage());
            return false;
        }
    }

    private Claims getClaims(@NonNull String token, SecretKey key) {
        return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
    }
}