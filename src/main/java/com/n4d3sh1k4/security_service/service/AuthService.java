package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.common.exception.*;
import com.n4d3sh1k4.security_service.domain.model.security.PasswordResetToken;
import com.n4d3sh1k4.security_service.domain.model.security.RefreshToken;
import com.n4d3sh1k4.security_service.domain.model.security.VerificationToken;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.repository.PasswordResetTokenRepository;
import com.n4d3sh1k4.security_service.domain.repository.RoleRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import com.n4d3sh1k4.security_service.domain.repository.VerificationTokenRepository;
import com.n4d3sh1k4.security_service.dto.AuthServiceResult;
import com.n4d3sh1k4.security_service.dto.event.NotificationEmailEvent;
import com.n4d3sh1k4.security_service.dto.event.PasswordResetEvent;
import com.n4d3sh1k4.security_service.dto.request_dto.LoginRequest;
import com.n4d3sh1k4.security_service.dto.request_dto.RegisterRequest;
import com.n4d3sh1k4.security_service.jwt.JwtProvider;
import com.n4d3sh1k4.security_service.utils.CookieUtils;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.security.auth.login.AccountLockedException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    @Value("${email.resend.activated.time}")
    String emailResendActivatedTime;

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
            throw new UserAlreadyExistsException("A user with this email already exists");
        }

        String encodedPassword = passwordEncoder.encode(req.getPassword());

        User user = new User();
        user.setEmail(req.getEmail());
        user.setPasswordHash(encodedPassword);
        user.setRoles(roleRepository.findByName("USER"));
        user.setUsername(req.getEmail().split("@")[0]);
        userRepository.save(user);

        String tokenValue = UUID.randomUUID().toString();
        VerificationToken verificationToken = new VerificationToken();
        verificationToken.setUser(user);
        verificationToken.setToken(tokenValue);
        verificationToken.setExpiryDate(Instant.now().plus(Duration.ofHours(1)));
        verificationTokenRepository.save(verificationToken);

        eventPublisher.publishEvent(new NotificationEmailEvent(
                user.getEmail(),
                req.getEmail().split("@")[0],
                tokenValue
        ));
    }

    @Transactional
    public void activateUser(String tokenValue) {
        VerificationToken verificationToken = verificationTokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new TokenNotFoundException("Activate token not found or provided", "NOT_FOUND", HttpStatus.NOT_FOUND));

        if (verificationToken.getExpiryDate().isBefore(Instant.now())) {
            verificationTokenRepository.delete(verificationToken);
            throw new TokenNotFoundException("This link is no longer valid.", "LINK_EXPIRED", HttpStatus.GONE);
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
                .orElseThrow(() -> new UserNotFoundException("User with this email not found."));

        if (user.getEnabled()) {
            throw new UserAlreadyActivatedException("The account has already been verified");
        }

        verificationTokenRepository.findByUser(user).ifPresent(token -> {
            if (token.getCreatedAt() == null) {
                throw new TokenCreationException("The old activation token exists, but its creation date is NULL.");
            }

            if (token.getCreatedAt().isAfter(LocalDateTime.now().minusMinutes(Integer.parseInt(emailResendActivatedTime)))) {
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
                user.getUsername(),
                tokenValue
        ));

        log.info("Resent confirmation token to: {}", email);
    }

    public AuthServiceResult loginUser(LoginRequest req) {
        User user = userRepository.findByEmail(req.getEmail())
            .orElseThrow(() -> new ContentNotFoundException("User not found"));

        if (user.getLockTime() != null) {
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
            throw new ContentNotFoundException("No refresh token provided");
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
            .orElseThrow(() -> new TokenNotFoundException("Refresh token not found or provided.","REFRESH_TOKEN_NOT_FOUND", HttpStatus.NOT_FOUND));

        User user = oldToken.getUser();
        boolean rememberMe = oldToken.isRememberMe();

        return new AuthServiceResult(
                jwtProvider.generateAccessToken(user),
                cookieUtils.generateRefreshTokenCookie(user, rememberMe).toString()
        );
    }

    @Transactional
    public void createPasswordResetToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User with this email not found."));

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
                .orElseThrow(() -> new TokenNotFoundException("Token no found.","TOKEN_NOT_FOUND", HttpStatus.NOT_FOUND));

        if (resetToken.isExpired()) {
            passwordResetTokenRepository.delete(resetToken);
            throw new TokenNotFoundException("Token expired.","TOKEN_EXPIRED", HttpStatus.GONE);
        }
        User user = resetToken.getUser();
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        refreshTokenService.deleteByUser(user);
        passwordResetTokenRepository.delete(resetToken);
    }
}