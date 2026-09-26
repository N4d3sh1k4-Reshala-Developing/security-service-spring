package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.common.exception.*;
import com.n4d3sh1k4.security_service.domain.model.security.RefreshToken;
import com.n4d3sh1k4.security_service.domain.model.security.Token;
import com.n4d3sh1k4.security_service.domain.model.security.TokenType;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.model.users.UserIdentity;
import com.n4d3sh1k4.security_service.domain.repository.*;
import com.n4d3sh1k4.security_service.dto.AuthServiceResult;
import com.n4d3sh1k4.security_service.dto.event.LoginEvent;
import com.n4d3sh1k4.security_service.dto.event.NotificationEmailEvent;
import com.n4d3sh1k4.security_service.dto.event.PasswordResetEvent;
import com.n4d3sh1k4.security_service.dto.event.UserRegisteredInternalEvent;
import com.n4d3sh1k4.security_service.dto.request_dto.LinkSocialRequest;
import com.n4d3sh1k4.security_service.dto.request_dto.LoginRequest;
import com.n4d3sh1k4.security_service.dto.request_dto.RegisterRequest;
import com.n4d3sh1k4.security_service.jwt.JwtProvider;
import com.n4d3sh1k4.security_service.utils.CookieUtils;
import io.jsonwebtoken.Claims;
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

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    @Value("${token.activation.activate.ttl}")
    String accountActivationTokenTtl;

    @Value("${token.activation.resend.ttl}")
    String accountActivationResendTokenTtl;

    @Value("${token.password.reset.ttl}")
    String passwordResetTokenTtl;

    @Value("${email.send.cooldown}")
    String accountActivationEmailResendCooldown;

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final TokenRepository tokenRepository;
    private final UserIdentityRepository userIdentityRepository;

    private final RefreshTokenService refreshTokenService;

    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final CookieUtils cookieUtils;
    private final AuthenticationManager authenticationManager;
    private final UserGeoService userGeoService;

    private final ApplicationEventPublisher eventPublisher;
    private final OutboxPublisher outboxPublisher;


    @Transactional
    public void registerUser(RegisterRequest req) {
        if (userRepository.findByEmail(req.getEmail().toLowerCase()).isPresent()) {
            throw new UserAlreadyExistsException("A user with this email already exists");
        }

        String encodedPassword = passwordEncoder.encode(req.getPassword());

        User user = new User();
        user.setEmail(req.getEmail().toLowerCase());
        user.setUsername(user.getEmail().split("@", 2)[0]);
        user.setPasswordHash(encodedPassword);
        user.setRoles(roleRepository.findByName("USER"));
        userRepository.save(user);

        String tokenValue = UUID.randomUUID().toString();
        Token verificationToken = Token.builder()
                .user(user)
                .token(tokenValue)
                .expiryDate(Instant.now().plus(Duration.ofMinutes(Long.parseLong(accountActivationTokenTtl))))
                .type(TokenType.VERIFICATION)
                .build();
        tokenRepository.save(verificationToken);

        eventPublisher.publishEvent(new UserRegisteredInternalEvent(
                user.getId(),
                user.getEmail(),
                null
        ));

        log.info("Username: {}",  user.getUsername());
        eventPublisher.publishEvent(new NotificationEmailEvent(
                user.getEmail(),
                user.getUsername(),
                tokenValue,
                accountActivationTokenTtl
        ));

        log.info("User registered: userId={}, email={}", user.getId(), user.getEmail());
    }

    @Transactional
    public void activateUser(String tokenValue) {
        Token token = tokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new TokenNotFoundException("Activate token not found or provided", "NOT_FOUND", HttpStatus.NOT_FOUND));

        if (token.isExpired()) {
            tokenRepository.delete(token);
            throw new TokenNotFoundException("This link is no longer valid.", "LINK_EXPIRED", HttpStatus.GONE);
        }

        User user = token.getUser();
        user.setEnabled(true);
        userRepository.save(user);

        tokenRepository.delete(token);

        log.info("User {} successfully activated", user.getEmail());
    }

    @Transactional
    public void resendConfirmToken(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User with this email not found."));

        if (user.getEnabled()) {
            throw new UserAlreadyActivatedException("The account has already been verified");
        }

        tokenRepository.findByUserAndType(user, TokenType.VERIFICATION).ifPresent(t -> {
            if (t.getCreatedAt() == null) {
                throw new TokenCreationException("The old activation token exists, but its creation date is NULL.");
            }

            if (t.getCreatedAt().isAfter(LocalDateTime.now().minusMinutes(Integer.parseInt(accountActivationEmailResendCooldown)))) {
                throw new TooManyRequestsException("Too fast!");
            }
        });

        tokenRepository.deleteByUserAndType(user, TokenType.VERIFICATION);

        String tokenValue = UUID.randomUUID().toString();
        Token verificationToken = Token.builder()
                .user(user)
                .token(tokenValue)
                .expiryDate(Instant.now().plus(Duration.ofMinutes(Long.parseLong(accountActivationResendTokenTtl))))
                .type(TokenType.VERIFICATION)
                .build();
        tokenRepository.save(verificationToken);


        log.info("Username: {}",  user.getUsername());
        eventPublisher.publishEvent(new NotificationEmailEvent(
                user.getEmail(),
                user.getUsername(),
                tokenValue,
                accountActivationTokenTtl
        ));

        log.info("Resent confirmation token to: {}", email);
    }

    public AuthServiceResult loginUser(LoginRequest req, String ipAddress, String userAgent) {
        User user = userRepository.findByEmail(req.getEmail())
            .orElseThrow(() -> new ContentNotFoundException("User not found"));

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

        String city = userGeoService.resolveCity(ipAddress);

        outboxPublisher.publish("user.login.email",
                new LoginEvent(user.getEmail(), ipAddress, userAgent, Instant.now(), city));

        log.info("Login success: userId={}, email={}, ip={}", user.getId(), user.getEmail(), ipAddress);

        return new AuthServiceResult(
                jwtProvider.generateAccessToken(user, city),
                cookieUtils.generateRefreshTokenCookie(user, req.isRememberMe(), userAgent, ipAddress, city).toString()
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
    public AuthServiceResult refreshToken(String refreshToken, String userAgent, String ip) {
        RefreshToken oldToken = refreshTokenService.findByToken(refreshToken)
            .orElseThrow(() -> new TokenNotFoundException("Refresh token not found or provided.","REFRESH_TOKEN_NOT_FOUND", HttpStatus.NOT_FOUND));

        if (oldToken.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenService.deleteByToken(refreshToken);
            throw new TokenNotFoundException("Refresh token expired", "REFRESH_TOKEN_EXPIRED", HttpStatus.UNAUTHORIZED);
        }

        User user = oldToken.getUser();
        boolean rememberMe = oldToken.isRememberMe();

        log.info("Token refresh: userId={}, email={}, ip={}", user.getId(), user.getEmail(), ip);
        refreshTokenService.deleteByToken(refreshToken);

        String city = userGeoService.resolveCity(ip);

        return new AuthServiceResult(
                jwtProvider.generateAccessToken(user, city),
                cookieUtils.generateRefreshTokenCookie(user, rememberMe, userAgent, ip, city).toString()
        );
    }

    @Transactional
    public AuthServiceResult oauthBootstrap(String accessToken, String userAgent, String ip) {
        if (!jwtProvider.validateAccessToken(accessToken)) {
            throw new TokenNotFoundException("Access token invalid", "ACCESS_TOKEN_INVALID", HttpStatus.UNAUTHORIZED);
        }

        Claims claims = jwtProvider.getAccessClaims(accessToken);
        UUID userId = UUID.fromString(claims.getSubject());
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        log.info("OAuth bootstrap: userId={}, email={}, ip={}", user.getId(), user.getEmail(), ip);
        String city = userGeoService.resolveCity(ip);

        return new AuthServiceResult(
                jwtProvider.generateAccessToken(user, city),
                cookieUtils.generateRefreshTokenCookie(user, true, userAgent, ip, city).toString()
        );
    }

    @Transactional
    public void createPasswordResetToken(String email) {
        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null) {
            log.warn("Password reset requested for unknown email: {}", email);
            return;
        }

        tokenRepository.findByUserAndType(user, TokenType.PASSWORD_RESET).ifPresent(t -> {
            if (t.getCreatedAt().isAfter(LocalDateTime.now().minusMinutes(Long.parseLong(accountActivationEmailResendCooldown)))) {
                throw new TooManyRequestsException("Too fast!");
            }
        });

        tokenRepository.deleteByUserAndType(user, TokenType.PASSWORD_RESET);

        String tokenValue = UUID.randomUUID().toString();
        Token resetToken = Token.builder()
                .user(user)
                .token(tokenValue)
                .expiryDate(Instant.now().plus(Duration.ofMinutes(Long.parseLong(passwordResetTokenTtl))))
                .type(TokenType.PASSWORD_RESET)
                .build();
        tokenRepository.save(resetToken);

        eventPublisher.publishEvent(new PasswordResetEvent(user.getEmail(), tokenValue, passwordResetTokenTtl));

        log.info("Password reset token issued: userId={}, email={}, ttl={}min", user.getId(), user.getEmail(), passwordResetTokenTtl);
    }

    @Transactional
    public void resetPassword(String token, String newPassword) {
        Token resetToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new TokenNotFoundException("Token no found.","TOKEN_NOT_FOUND", HttpStatus.NOT_FOUND));

        if (resetToken.isExpired()) {
            tokenRepository.delete(resetToken);
            throw new TokenNotFoundException("Token expired.","TOKEN_EXPIRED", HttpStatus.GONE);
        }
        User user = resetToken.getUser();
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        refreshTokenService.deleteByUser(user);
        tokenRepository.delete(resetToken);

        log.info("Password reset completed: userId={}, email={}", user.getId(), user.getEmail());
    }

    @Transactional
    public AuthServiceResult linkSocialAccount(LinkSocialRequest request, String userAgent, String ip) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new UserNotFoundException("User not found"));

        boolean exists = userIdentityRepository.findByProviderAndProviderUserId(request.getProvider(), request.getProviderUserId()).isPresent();

        if (!exists) {
            UserIdentity identity = new UserIdentity();
            identity.setUser(user);
            identity.setProvider(request.getProvider());
            identity.setProviderUserId(request.getProviderUserId());
            userIdentityRepository.save(identity);
            log.info("Successfully linked {} identity to user {}", request.getProvider(), user.getEmail());
        }

        String city = userGeoService.resolveCity(ip);

        return new AuthServiceResult(
                jwtProvider.generateAccessToken(user, city),
                cookieUtils.generateRefreshTokenCookie(user, true, userAgent, ip, city).toString()
        );
    }
}