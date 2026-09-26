package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.common.exception.BaseException;
import com.n4d3sh1k4.common.exception.ContentNotFoundException;
import com.n4d3sh1k4.common.exception.TokenCreationException;
import com.n4d3sh1k4.common.exception.TokenNotFoundException;
import com.n4d3sh1k4.common.exception.TooManyRequestsException;
import com.n4d3sh1k4.common.exception.UserAlreadyActivatedException;
import com.n4d3sh1k4.common.exception.UserAlreadyExistsException;
import com.n4d3sh1k4.common.exception.UserNotFoundException;
import com.n4d3sh1k4.security_service.domain.model.security.RefreshToken;
import com.n4d3sh1k4.security_service.domain.model.security.Token;
import com.n4d3sh1k4.security_service.domain.model.security.TokenType;
import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import com.n4d3sh1k4.security_service.domain.model.users.Role;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.model.users.UserIdentity;
import com.n4d3sh1k4.security_service.domain.repository.RoleRepository;
import com.n4d3sh1k4.security_service.domain.repository.TokenRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserIdentityRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class AuthServiceTest {

    private static final String EMAIL = "user@example.com";
    private static final String PASSWORD = "Password#4848";

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private TokenRepository tokenRepository;

    @Mock
    private UserIdentityRepository userIdentityRepository;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtProvider jwtProvider;

    @Mock
    private CookieUtils cookieUtils;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserGeoService userGeoService;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    @Mock
    private OutboxPublisher outboxPublisher;

    @InjectMocks
    private AuthService authService;

    private User user;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "accountActivationTokenTtl", "60");
        ReflectionTestUtils.setField(authService, "accountActivationResendTokenTtl", "60");
        ReflectionTestUtils.setField(authService, "passwordResetTokenTtl", "60");
        ReflectionTestUtils.setField(authService, "accountActivationEmailResendCooldown", "5");

        user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail(EMAIL);
        user.setPasswordHash("encoded-hash");
        user.setEnabled(false);
        user.setAccountNonLocked(true);
        user.setFailedAttempts(0);
    }

    private RegisterRequest registerRequest() {
        RegisterRequest req = new RegisterRequest();
        req.setEmail(EMAIL);
        req.setPassword(PASSWORD);
        req.setConfirmPassword(PASSWORD);
        return req;
    }

    private LoginRequest loginRequest(boolean rememberMe) {
        LoginRequest req = new LoginRequest();
        req.setEmail(EMAIL);
        req.setPassword(PASSWORD);
        req.setRememberMe(rememberMe);
        return req;
    }

    private Token validToken(User owner, TokenType type) {
        return Token.builder()
                .id(UUID.randomUUID())
                .user(owner)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusSeconds(3600))
                .createdAt(LocalDateTime.now())
                .type(type)
                .build();
    }

    private Token expiredToken(User owner, TokenType type) {
        return Token.builder()
                .id(UUID.randomUUID())
                .user(owner)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().minusSeconds(60))
                .createdAt(LocalDateTime.now())
                .type(type)
                .build();
    }

    private RefreshToken validRefreshToken(User owner) {
        RefreshToken rt = new RefreshToken();
        rt.setUser(owner);
        rt.setToken("refresh-token");
        rt.setExpiryDate(Instant.now().plusSeconds(3600));
        rt.setRememberMe(true);
        return rt;
    }

    // ---------- registerUser ----------

    @Test
    void registerUser_whenEmailAlreadyExists_throwsUserAlreadyExists() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.registerUser(registerRequest()))
                .isInstanceOf(UserAlreadyExistsException.class)
                .extracting(e -> ((BaseException) e).getCode())
                .isEqualTo("USER_ALREADY_EXISTS");

        verify(userRepository, never()).save(any(User.class));
        verify(tokenRepository, never()).save(any(Token.class));
    }

    @Test
    void registerUser_createsUserVerificationTokenAndPublishesEvents() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());
        when(passwordEncoder.encode(PASSWORD)).thenReturn("encoded-hash");
        when(roleRepository.findByName("USER")).thenReturn(List.of(new Role("USER")));

        authService.registerUser(registerRequest());

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(userCaptor.capture());
        User saved = userCaptor.getValue();
        assertThat(saved.getEmail()).isEqualTo(EMAIL);
        assertThat(saved.getUsername()).isEqualTo("user");
        assertThat(saved.getPasswordHash()).isEqualTo("encoded-hash");
        assertThat(saved.getRoles()).extracting(Role::getName).containsExactly("USER");

        ArgumentCaptor<Token> tokenCaptor = ArgumentCaptor.forClass(Token.class);
        verify(tokenRepository).save(tokenCaptor.capture());
        Token savedToken = tokenCaptor.getValue();
        assertThat(savedToken.getType()).isEqualTo(TokenType.VERIFICATION);
        assertThat(savedToken.getUser()).isSameAs(saved);
        assertThat(savedToken.getExpiryDate()).isAfter(Instant.now().plusSeconds(59 * 60));

        verify(eventPublisher).publishEvent(new UserRegisteredInternalEvent(
                saved.getId(), EMAIL, null));

        verify(eventPublisher).publishEvent(new NotificationEmailEvent(
                EMAIL, "user", savedToken.getToken(), "60"));
    }

    // ---------- activateUser ----------

    @Test
    void activateUser_whenTokenNotFound_throwsTokenNotFound() {
        when(tokenRepository.findByToken("missing")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.activateUser("missing"))
                .isInstanceOf(TokenNotFoundException.class)
                .satisfies(e -> {
                    assertThat(((BaseException) e).getCode()).isEqualTo("NOT_FOUND");
                    assertThat(((BaseException) e).getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
                });
    }

    @Test
    void activateUser_whenTokenExpired_deletesTokenAndThrows() {
        Token expired = expiredToken(user, TokenType.VERIFICATION);
        when(tokenRepository.findByToken(expired.getToken())).thenReturn(Optional.of(expired));

        assertThatThrownBy(() -> authService.activateUser(expired.getToken()))
                .isInstanceOf(TokenNotFoundException.class)
                .satisfies(e -> {
                    assertThat(((BaseException) e).getCode()).isEqualTo("LINK_EXPIRED");
                    assertThat(((BaseException) e).getStatus()).isEqualTo(HttpStatus.GONE);
                });

        verify(tokenRepository).delete(expired);
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    void activateUser_whenTokenValid_enablesUser() {
        Token token = validToken(user, TokenType.VERIFICATION);
        when(tokenRepository.findByToken(token.getToken())).thenReturn(Optional.of(token));

        authService.activateUser(token.getToken());

        assertThat(user.getEnabled()).isTrue();
        verify(userRepository).save(user);
        verify(tokenRepository).delete(token);
    }

    // ---------- resendConfirmToken ----------

    @Test
    void resendConfirmToken_whenUserNotFound_throwsUserNotFound() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.resendConfirmToken(EMAIL))
                .isInstanceOf(UserNotFoundException.class);
    }

    @Test
    void resendConfirmToken_whenUserAlreadyEnabled_throwsUserAlreadyActivated() {
        user.setEnabled(true);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.resendConfirmToken(EMAIL))
                .isInstanceOf(UserAlreadyActivatedException.class);
    }

    @Test
    void resendConfirmToken_whenExistingTokenHasNullCreatedAt_throwsTokenCreation() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        Token token = validToken(user, TokenType.VERIFICATION);
        token.setCreatedAt(null);
        when(tokenRepository.findByUserAndType(user, TokenType.VERIFICATION))
                .thenReturn(Optional.of(token));

        assertThatThrownBy(() -> authService.resendConfirmToken(EMAIL))
                .isInstanceOf(TokenCreationException.class);
    }

    @Test
    void resendConfirmToken_whenTooSoon_throwsTooManyRequests() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        Token recent = validToken(user, TokenType.VERIFICATION);
        recent.setCreatedAt(LocalDateTime.now().minusMinutes(1));
        when(tokenRepository.findByUserAndType(user, TokenType.VERIFICATION))
                .thenReturn(Optional.of(recent));

        assertThatThrownBy(() -> authService.resendConfirmToken(EMAIL))
                .isInstanceOf(TooManyRequestsException.class);
    }

    @Test
    void resendConfirmToken_whenCooldownPassed_createsNewTokenAndPublishesEvent() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        Token old = validToken(user, TokenType.VERIFICATION);
        old.setCreatedAt(LocalDateTime.now().minusMinutes(10));
        when(tokenRepository.findByUserAndType(user, TokenType.VERIFICATION))
                .thenReturn(Optional.of(old));

        authService.resendConfirmToken(EMAIL);

        verify(tokenRepository).deleteByUserAndType(user, TokenType.VERIFICATION);

        ArgumentCaptor<Token> tokenCaptor = ArgumentCaptor.forClass(Token.class);
        verify(tokenRepository).save(tokenCaptor.capture());
        Token saved = tokenCaptor.getValue();
        assertThat(saved.getType()).isEqualTo(TokenType.VERIFICATION);
        assertThat(saved.getUser()).isSameAs(user);
        assertThat(saved.getExpiryDate()).isAfter(Instant.now().plusSeconds(59 * 60));

        verify(eventPublisher).publishEvent(new NotificationEmailEvent(EMAIL, null, saved.getToken(), "60"));
    }

    @Test
    void resendConfirmToken_whenNoExistingToken_createsTokenAndPublishesEvent() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(tokenRepository.findByUserAndType(user, TokenType.VERIFICATION))
                .thenReturn(Optional.empty());

        authService.resendConfirmToken(EMAIL);

        verify(tokenRepository).deleteByUserAndType(user, TokenType.VERIFICATION);
        ArgumentCaptor<Token> tokenCaptor = ArgumentCaptor.forClass(Token.class);
        verify(tokenRepository).save(tokenCaptor.capture());
        verify(eventPublisher).publishEvent(new NotificationEmailEvent(EMAIL, null, tokenCaptor.getValue().getToken(), "60"));
    }

    // ---------- loginUser ----------

    @Test
    void loginUser_whenUserNotFound_throwsContentNotFound() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.loginUser(loginRequest(false), "127.0.0.1", "test-agent"))
                .isInstanceOf(ContentNotFoundException.class);
    }

    @Test
    void loginUser_whenLockedAndLockTimeInFuture_throwsTooManyRequests() {
        user.setAccountNonLocked(false);
        user.setLockTime(Instant.now().plusSeconds(300));
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.loginUser(loginRequest(false), "127.0.0.1", "test-agent"))
                .isInstanceOf(TooManyRequestsException.class);

        verify(authenticationManager, never()).authenticate(any());
    }

    @Test
    void loginUser_whenLockExpired_unlocksAccountAndSucceeds() {
        user.setAccountNonLocked(false);
        user.setLockTime(Instant.now().minusSeconds(60));
        user.setFailedAttempts(3);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(mock(Authentication.class));
        when(jwtProvider.generateAccessToken(eq(user), any())).thenReturn("access-token");
        when(cookieUtils.generateRefreshTokenCookie(eq(user), eq(false), any(), any(), any()))
                .thenReturn(ResponseCookie.from("refreshToken", "abc").path("/").build());

        AuthServiceResult result = authService.loginUser(loginRequest(false), "127.0.0.1", "test-agent");

        assertThat(user.isAccountNonLocked()).isTrue();
        assertThat(user.getFailedAttempts()).isZero();
        assertThat(user.getLockTime()).isNull();
        verify(userRepository).save(user);
        assertThat(result.getAccesToken()).isEqualTo("access-token");
    }

    @Test
    void loginUser_whenValidCredentials_returnsTokensAndPublishesLoginEvent() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(mock(Authentication.class));
when(jwtProvider.generateAccessToken(eq(user), any())).thenReturn("access-token");
        when(cookieUtils.generateRefreshTokenCookie(eq(user), eq(true), any(), any(), any()))
                .thenReturn(ResponseCookie.from("refreshToken", "refresh").path("/").build());
        when(userGeoService.resolveCity(any())).thenReturn("Москва");

        AuthServiceResult result = authService.loginUser(loginRequest(true), "192.168.0.1", "Mozilla/5.0");

        assertThat(result.getAccesToken()).isEqualTo("access-token");
        assertThat(result.getCookie()).isEqualTo(
                ResponseCookie.from("refreshToken", "refresh").path("/").build().toString());

        ArgumentCaptor<LoginEvent> eventCaptor = ArgumentCaptor.forClass(LoginEvent.class);
        verify(outboxPublisher).publish(eq("user.login.email"), eventCaptor.capture());
        assertThat(eventCaptor.getValue().email()).isEqualTo(EMAIL);
        assertThat(eventCaptor.getValue().ipAddress()).isEqualTo("192.168.0.1");
        assertThat(eventCaptor.getValue().userAgent()).isEqualTo("Mozilla/5.0");
        assertThat(eventCaptor.getValue().city()).isEqualTo("Москва");
    }

    // ---------- logoutUser ----------

    @Test
    void logoutUser_whenRefreshTokenNull_throwsContentNotFound() {
        assertThatThrownBy(() -> authService.logoutUser(user.getId().toString(), null))
                .isInstanceOf(ContentNotFoundException.class);
    }

    @Test
    void logoutUser_whenTokenBelongsToUser_deletesToken() {
        when(refreshTokenService.findByToken("refresh-token"))
                .thenReturn(Optional.of(validRefreshToken(user)));
        when(cookieUtils.getCleanRefreshTokenCookie())
                .thenReturn(ResponseCookie.from("refreshToken", "").maxAge(0).path("/").build());

        AuthServiceResult result = authService.logoutUser(user.getId().toString(), "refresh-token");

        verify(refreshTokenService).deleteByToken("refresh-token");
        assertThat(result.getCookie()).contains("refreshToken");
    }

    @Test
    void logoutUser_whenTokenBelongsToAnotherUser_doesNotDelete() {
        User other = new User();
        other.setId(UUID.randomUUID());
        other.setEmail("other@example.com");
        when(refreshTokenService.findByToken("refresh-token"))
                .thenReturn(Optional.of(validRefreshToken(other)));
        when(cookieUtils.getCleanRefreshTokenCookie())
                .thenReturn(ResponseCookie.from("refreshToken", "").maxAge(0).path("/").build());

        authService.logoutUser(user.getId().toString(), "refresh-token");

        verify(refreshTokenService, never()).deleteByToken(anyString());
    }

    @Test
    void logoutUser_whenTokenNotFound_stillReturnsCleanCookie() {
        when(refreshTokenService.findByToken("missing")).thenReturn(Optional.empty());
        when(cookieUtils.getCleanRefreshTokenCookie())
                .thenReturn(ResponseCookie.from("refreshToken", "").maxAge(0).path("/").build());

        AuthServiceResult result = authService.logoutUser(user.getId().toString(), "missing");

        assertThat(result.getCookie()).contains("Max-Age=0");
        verify(refreshTokenService, never()).deleteByToken(anyString());
    }

    // ---------- refreshToken ----------

    @Test
    void refreshToken_whenTokenNotFound_throwsTokenNotFound() {
        when(refreshTokenService.findByToken("missing")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.refreshToken("missing", null, null))
                .isInstanceOf(TokenNotFoundException.class)
                .satisfies(e -> {
                    assertThat(((BaseException) e).getCode()).isEqualTo("REFRESH_TOKEN_NOT_FOUND");
                    assertThat(((BaseException) e).getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
                });
    }

    @Test
    void refreshToken_whenTokenExpired_deletesTokenAndThrows() {
        RefreshToken rt = validRefreshToken(user);
        rt.setExpiryDate(Instant.now().minusSeconds(60));
        when(refreshTokenService.findByToken("refresh-token")).thenReturn(Optional.of(rt));

        assertThatThrownBy(() -> authService.refreshToken("refresh-token", null, null))
                .isInstanceOf(TokenNotFoundException.class)
                .satisfies(e -> {
                    assertThat(((BaseException) e).getCode()).isEqualTo("REFRESH_TOKEN_EXPIRED");
                    assertThat(((BaseException) e).getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
                });

        verify(refreshTokenService).deleteByToken("refresh-token");
    }

    @Test
    void refreshToken_whenValid_returnsNewTokensWithRememberMePreserved() {
        when(refreshTokenService.findByToken("refresh-token")).thenReturn(Optional.of(validRefreshToken(user)));
        when(jwtProvider.generateAccessToken(eq(user), any())).thenReturn("new-access");
        when(cookieUtils.generateRefreshTokenCookie(eq(user), eq(true), eq(null), eq(null), any()))
                .thenReturn(ResponseCookie.from("refreshToken", "new-refresh").path("/").build());

        AuthServiceResult result = authService.refreshToken("refresh-token", null, null);

        assertThat(result.getAccesToken()).isEqualTo("new-access");
        assertThat(result.getCookie()).contains("new-refresh");
        verify(cookieUtils).generateRefreshTokenCookie(eq(user), eq(true), eq(null), eq(null), any());
    }

    // ---------- createPasswordResetToken ----------

    @Test
    void createPasswordResetToken_whenUserNotFound_doesNothing() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        authService.createPasswordResetToken(EMAIL);

        verify(tokenRepository, never()).save(any(Token.class));
    }

    @Test
    void createPasswordResetToken_whenTooSoon_throwsTooManyRequests() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        Token recent = validToken(user, TokenType.PASSWORD_RESET);
        recent.setCreatedAt(LocalDateTime.now().minusMinutes(1));
        when(tokenRepository.findByUserAndType(user, TokenType.PASSWORD_RESET))
                .thenReturn(Optional.of(recent));

        assertThatThrownBy(() -> authService.createPasswordResetToken(EMAIL))
                .isInstanceOf(TooManyRequestsException.class);
    }

    @Test
    void createPasswordResetToken_createsTokenAndPublishesEvent() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(tokenRepository.findByUserAndType(user, TokenType.PASSWORD_RESET))
                .thenReturn(Optional.empty());

        authService.createPasswordResetToken(EMAIL);

        verify(tokenRepository).deleteByUserAndType(user, TokenType.PASSWORD_RESET);

        ArgumentCaptor<Token> tokenCaptor = ArgumentCaptor.forClass(Token.class);
        verify(tokenRepository).save(tokenCaptor.capture());
        Token saved = tokenCaptor.getValue();
        assertThat(saved.getType()).isEqualTo(TokenType.PASSWORD_RESET);
        assertThat(saved.getUser()).isSameAs(user);

        ArgumentCaptor<PasswordResetEvent> eventCaptor = ArgumentCaptor.forClass(PasswordResetEvent.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        assertThat(eventCaptor.getValue().email()).isEqualTo(EMAIL);
        assertThat(eventCaptor.getValue().token()).isEqualTo(saved.getToken());
        assertThat(eventCaptor.getValue().passwordResetTokenTtl()).isEqualTo("60");
    }

    // ---------- resetPassword ----------

    @Test
    void resetPassword_whenTokenNotFound_throwsTokenNotFound() {
        when(tokenRepository.findByToken("missing")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.resetPassword("missing", PASSWORD))
                .isInstanceOf(TokenNotFoundException.class)
                .satisfies(e -> {
                    assertThat(((BaseException) e).getCode()).isEqualTo("TOKEN_NOT_FOUND");
                    assertThat(((BaseException) e).getStatus()).isEqualTo(HttpStatus.NOT_FOUND);
                });
    }

    @Test
    void resetPassword_whenTokenExpired_deletesTokenAndThrows() {
        Token expired = expiredToken(user, TokenType.PASSWORD_RESET);
        when(tokenRepository.findByToken(expired.getToken())).thenReturn(Optional.of(expired));

        assertThatThrownBy(() -> authService.resetPassword(expired.getToken(), PASSWORD))
                .isInstanceOf(TokenNotFoundException.class)
                .satisfies(e -> {
                    assertThat(((BaseException) e).getCode()).isEqualTo("TOKEN_EXPIRED");
                    assertThat(((BaseException) e).getStatus()).isEqualTo(HttpStatus.GONE);
                });

        verify(tokenRepository).delete(expired);
    }

    @Test
    void resetPassword_whenValid_updatesPasswordAndRevokesTokens() {
        Token token = validToken(user, TokenType.PASSWORD_RESET);
        when(tokenRepository.findByToken(token.getToken())).thenReturn(Optional.of(token));
        when(passwordEncoder.encode(PASSWORD)).thenReturn("new-encoded-hash");

        authService.resetPassword(token.getToken(), PASSWORD);

        assertThat(user.getPasswordHash()).isEqualTo("new-encoded-hash");
        verify(userRepository).save(user);
        verify(refreshTokenService).deleteByUser(user);
        verify(tokenRepository).delete(token);
    }

    // ---------- linkSocialAccount ----------

    @Test
    void linkSocialAccount_whenUserNotFound_throwsUserNotFound() {
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(mock(Authentication.class));
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        LinkSocialRequest req = new LinkSocialRequest();
        req.setEmail(EMAIL);
        req.setPassword(PASSWORD);
        req.setProvider(AuthProvider.YANDEX);
        req.setProviderUserId("ya-123");

        assertThatThrownBy(() -> authService.linkSocialAccount(req, null, null))
                .isInstanceOf(UserNotFoundException.class);
    }

    @Test
    void linkSocialAccount_whenIdentityMissing_savesIdentityAndReturnsTokens() {
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(mock(Authentication.class));
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        when(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.YANDEX, "ya-123"))
                .thenReturn(Optional.empty());
        when(jwtProvider.generateAccessToken(eq(user), any())).thenReturn("access-token");
        when(cookieUtils.generateRefreshTokenCookie(eq(user), eq(true), eq(null), eq(null), any()))
                .thenReturn(ResponseCookie.from("refreshToken", "rt").path("/").build());

        LinkSocialRequest req = new LinkSocialRequest();
        req.setEmail(EMAIL);
        req.setPassword(PASSWORD);
        req.setProvider(AuthProvider.YANDEX);
        req.setProviderUserId("ya-123");

        AuthServiceResult result = authService.linkSocialAccount(req, null, null);

        ArgumentCaptor<UserIdentity> identityCaptor = ArgumentCaptor.forClass(UserIdentity.class);
        verify(userIdentityRepository).save(identityCaptor.capture());
        assertThat(identityCaptor.getValue().getUser()).isSameAs(user);
        assertThat(identityCaptor.getValue().getProvider()).isEqualTo(AuthProvider.YANDEX);
        assertThat(identityCaptor.getValue().getProviderUserId()).isEqualTo("ya-123");

        assertThat(result.getAccesToken()).isEqualTo("access-token");
    }

    @Test
    void linkSocialAccount_whenIdentityExists_doesNotSaveAgain() {
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(mock(Authentication.class));
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));
        UserIdentity identity = new UserIdentity();
        identity.setUser(user);
        identity.setProvider(AuthProvider.YANDEX);
        identity.setProviderUserId("ya-123");
        when(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.YANDEX, "ya-123"))
                .thenReturn(Optional.of(identity));
        when(jwtProvider.generateAccessToken(eq(user), any())).thenReturn("access-token");
        when(cookieUtils.generateRefreshTokenCookie(eq(user), eq(true), eq(null), eq(null), any()))
                .thenReturn(ResponseCookie.from("refreshToken", "rt").path("/").build());

        LinkSocialRequest req = new LinkSocialRequest();
        req.setEmail(EMAIL);
        req.setPassword(PASSWORD);
        req.setProvider(AuthProvider.YANDEX);
        req.setProviderUserId("ya-123");

        authService.linkSocialAccount(req, null, null);

        verify(userIdentityRepository, never()).save(any(UserIdentity.class));
    }


}
