package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.security_service.domain.model.security.RefreshToken;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public List<RefreshToken> findAllByUserId(UUID userId) {
        return refreshTokenRepository.findAllByUserId(userId);
    }

    @Transactional
    public void deleteByUser(User user) {
        refreshTokenRepository.deleteByUser(user);
        log.info("All refresh tokens for user ID {} have been revoked", user.getId());
    }

    @Transactional
    public void deleteByToken(String token) {
        refreshTokenRepository.deleteByToken(token);
    }

    @Transactional
    public void deleteByUserIdExceptToken(UUID userId, String currentToken) {
        refreshTokenRepository.deleteByUserIdExceptToken(userId, currentToken);
        log.info("All refresh tokens for user {} except current session revoked", userId);
    }

    @Transactional
    public void deleteSessionById(UUID userId, UUID sessionId, String currentToken) {
        refreshTokenRepository.deleteSessionById(userId, sessionId, currentToken);
        log.info("Session {} for user {} revoked", sessionId, userId);
    }

    @Transactional
    public RefreshToken createRefreshToken(User user, boolean rememberMe, String userAgent, String ip, String city) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setToken(UUID.randomUUID().toString());

        Instant expiry = rememberMe ? Instant.now().plus(30, ChronoUnit.DAYS) : Instant.now().plus(1, ChronoUnit.DAYS);
        refreshToken.setExpiryDate(expiry);
        refreshToken.setRememberMe(rememberMe);
        refreshToken.setUserAgent(userAgent);
        refreshToken.setIp(ip);
        refreshToken.setCity(city);

        return refreshTokenRepository.save(refreshToken);
    }
}