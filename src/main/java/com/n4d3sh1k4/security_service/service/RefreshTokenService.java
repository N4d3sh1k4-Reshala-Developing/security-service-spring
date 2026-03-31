package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.security_service.domain.model.security.RefreshToken;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.repository.RefreshTokenRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public void deleteByUser(User user) {
        refreshTokenRepository.deleteByUser(user);
        log.info("All refresh tokens for user ID {} have been revoked", user.getId());
    }

    @Transactional
    public void deleteByToken(String token) {refreshTokenRepository.deleteByToken(token);}

    @Transactional
    public RefreshToken createRefreshToken(User user, boolean rememberMe) {
        refreshTokenRepository.deleteByUser(user);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID().toString());

        // Выставляем expiryDate в зависимости от флага
        Instant expiry = rememberMe ? Instant.now().plus(30, ChronoUnit.DAYS) : Instant.now().plus(1, ChronoUnit.DAYS);
        refreshToken.setExpiryDate(expiry);

        return refreshTokenRepository.save(refreshToken);
    }
}