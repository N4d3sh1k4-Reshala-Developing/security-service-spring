package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.security_service.domain.model.security.PasswordResetToken;
import com.n4d3sh1k4.security_service.domain.model.security.RefreshToken;
import com.n4d3sh1k4.security_service.domain.model.security.VerificationToken;
import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.repository.PasswordResetTokenRepository;
import com.n4d3sh1k4.security_service.domain.repository.RoleRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import com.n4d3sh1k4.security_service.domain.repository.VerificationTokenRepository;
import com.n4d3sh1k4.security_service.dto.AuthServiceResult;
import com.n4d3sh1k4.security_service.dto.event.NotificationEmailEvent;
import com.n4d3sh1k4.security_service.dto.event.PasswordResetEvent;
import com.n4d3sh1k4.security_service.dto.event.UserRegisteredInternalEvent;
import com.n4d3sh1k4.security_service.dto.request_dto.LoginRequest;
import com.n4d3sh1k4.security_service.dto.request_dto.RegisterRequest;
import com.n4d3sh1k4.security_service.exception.*;
import com.n4d3sh1k4.security_service.jwt.JwtProvider;
import com.n4d3sh1k4.security_service.utils.CookieUtils;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hibernate.validator.internal.util.stereotypes.Lazy;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final VerificationTokenRepository verificationTokenRepository;

    private final RefreshTokenService refreshTokenService;

    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final CookieUtils cookieUtils;
    private final AuthenticationManager authenticationManager;

    private final ApplicationEventPublisher eventPublisher;


    @Transactional
    public void registerUser(RegisterRequest req) {
        if (userRepository.findByEmail(req.getEmail()).isPresent()) {
            throw new UserAlreadyExistsException("A user with this email already exists!");
        }

        String encodedPassword = passwordEncoder.encode(req.getPassword());

        User user = new User();
        user.setEmail(req.getEmail());
        user.setPasswordHash(encodedPassword);
        user.setRoles(roleRepository.findByName("USER"));
        userRepository.save(user);

        String tokenValue = UUID.randomUUID().toString();
        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setUser(user);
        verificationToken.setToken(tokenValue);
        verificationToken.setExpiryDate(Instant.now().plus(Duration.ofHours(1)));
        verificationTokenRepository.save(verificationToken);

        eventPublisher.publishEvent(new UserRegisteredInternalEvent(
                user.getId(),
                req.getUsername(),
                user.getEmail()
        ));

        eventPublisher.publishEvent(new NotificationEmailEvent(
                user.getEmail(),
                req.getUsername(),
                tokenValue
        ));
    }

    @Transactional
    public void activateUser(String tokenValue) {
        VerificationToken verificationToken = verificationTokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new RuntimeException("Невалидный токен подтверждения"));

        if (verificationToken.getExpiryDate().isBefore(Instant.now())) {
            verificationTokenRepository.delete(verificationToken);
            throw new RuntimeException("Срок действия токена истек. Зарегистрируйтесь снова.");
        }

        User user = verificationToken.getUser();
        user.setEnabled(true);
        userRepository.save(user);

        verificationTokenRepository.delete(verificationToken);

        log.info("User {} successfully activated", user.getEmail());
    }

    @Transactional
    public void resendConfirmToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Пользователь с таким email не найден"));

        if (user.getEnabled()) {
            throw new RuntimeException("Аккаунт уже подтвержден. Попробуйте войти.");
        }

        verificationTokenRepository.findByUser(user).ifPresent(token -> {
            if (token.getCreatedAt() == null) {
                return;
            }

            if (token.getCreatedAt().isAfter(LocalDateTime.now().minusMinutes(15))) {
                throw new TooManyRequestsException("Too fast!");
            }
        });

        verificationTokenRepository.deleteByUser(user);

        String tokenValue = UUID.randomUUID().toString();
        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setUser(user);
        verificationToken.setToken(tokenValue);
        verificationToken.setExpiryDate(Instant.now().plus(Duration.ofHours(1)));
        verificationTokenRepository.save(verificationToken);

        eventPublisher.publishEvent(new NotificationEmailEvent(
                user.getEmail(),
                null,
                tokenValue
        ));

        log.info("Resent confirmation token to: {}", email);
    }

    public AuthServiceResult loginUser(LoginRequest req) {
        User user = userRepository.findByEmail(req.getEmail())
            .orElseThrow(() -> new BadCredentialsException("User not found"));

        if (!user.isAccountNonLocked() && user.getLockTime() != null) {
            if (user.getLockTime().isBefore(Instant.now())) {
                user.setAccountNonLocked(true);
                user.setFailedAttempts(0);
                user.setLockTime(null);
                userRepository.save(user);
            } else {
                throw new TooManyRequestsException("Account is locked. Try again later.");
            }
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        return new AuthServiceResult(
                jwtProvider.generateAccessToken(user),
                cookieUtils.generateRefreshTokenCookie(user, req.isRememberMe()).toString()
        );
    }

    @Transactional
    public AuthServiceResult logoutUser(String userId, String refreshToken) {
        if (refreshToken == null) {
            throw new BadCredentialsException("No refresh token provided");
        }

        var tokenOpt = refreshTokenService.findByToken(refreshToken);

        if (tokenOpt.isPresent()) {
            var tokenEntity = tokenOpt.get();

            if (tokenEntity.getUser().getId().toString().equals(userId)) {
                refreshTokenService.deleteByToken(refreshToken);
            }
        }
        return new AuthServiceResult(
                cookieUtils.getCleanRefreshTokenCookie().toString()
        );
    }

    @Transactional
    public AuthServiceResult refreshToken(String refreshToken) {
        RefreshToken oldToken = refreshTokenService.findByToken(refreshToken)
            .orElseThrow(TokenNotFoundException::new);

        User user = oldToken.getUser();
        boolean rememberMe = oldToken.isRememberMe(); // <-- ВОТ ОНО! Наследуем состояние

        return new AuthServiceResult(
                jwtProvider.generateAccessToken(user),
                cookieUtils.generateRefreshTokenCookie(user, rememberMe).toString()
        );
    }

    @Transactional
    public void createPasswordResetToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        passwordResetTokenRepository.findByUser(user).ifPresent(token -> {
            if (token.getCreatedAt().isAfter(LocalDateTime.now().minusMinutes(5))) {
                throw new TooManyRequestsException("Too fast!");
            }
        });

        passwordResetTokenRepository.deleteByUser(user);

        passwordResetTokenRepository.flush();

        String token = UUID.randomUUID().toString();
        PasswordResetToken myToken = new PasswordResetToken();
        myToken.setToken(token);
        myToken.setUser(user);
        myToken.setExpiryDate(LocalDateTime.now().plusMinutes(15));
        passwordResetTokenRepository.save(myToken);

        eventPublisher.publishEvent(new PasswordResetEvent(user.getEmail(), token));
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        PasswordResetToken resetToken = passwordResetTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid token"));

        if (resetToken.isExpired()) {
            passwordResetTokenRepository.delete(resetToken);
            throw new RuntimeException("Token expired");
        }
        User user = resetToken.getUser();
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        refreshTokenService.deleteByUser(user);
        passwordResetTokenRepository.delete(resetToken);
    }
}