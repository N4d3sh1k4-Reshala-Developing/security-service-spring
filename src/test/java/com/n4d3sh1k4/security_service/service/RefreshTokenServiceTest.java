package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.security_service.domain.model.security.RefreshToken;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.repository.RefreshTokenRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks
    private RefreshTokenService refreshTokenService;

    private User user() {
        User u = new User();
        u.setId(UUID.randomUUID());
        u.setEmail("user@example.com");
        return u;
    }

    private RefreshToken storedToken() {
        RefreshToken rt = new RefreshToken();
        rt.setUser(user());
        rt.setToken("token-value");
        rt.setExpiryDate(Instant.now().plusSeconds(3600));
        rt.setRememberMe(false);
        return rt;
    }

    @Test
    void findByToken_delegatesToRepository() {
        RefreshToken rt = storedToken();
        when(refreshTokenRepository.findByToken("token-value")).thenReturn(Optional.of(rt));

        assertThat(refreshTokenService.findByToken("token-value")).contains(rt);
        assertThat(refreshTokenService.findByToken("missing")).isEmpty();
    }

    @Test
    void deleteByUser_delegatesToRepository() {
        User user = user();
        refreshTokenService.deleteByUser(user);

        verify(refreshTokenRepository).deleteByUser(user);
    }

    @Test
    void deleteByToken_delegatesToRepository() {
        refreshTokenService.deleteByToken("token-value");

        verify(refreshTokenRepository).deleteByToken("token-value");
    }

    @Test
    void createRefreshToken_withRememberMe_createsThirtyDayToken() {
        User user = user();
        when(refreshTokenRepository.save(org.mockito.ArgumentMatchers.any(RefreshToken.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        RefreshToken saved = refreshTokenService.createRefreshToken(user, true, "Mozilla/5.0", "127.0.0.1", "Москва");

        assertThat(saved.getUser()).isSameAs(user);
        assertThat(saved.isRememberMe()).isTrue();
        assertThat(saved.getToken()).isNotNull();
        assertThat(UUID.fromString(saved.getToken())).isNotNull();
        assertThat(saved.getExpiryDate())
                .isCloseTo(Instant.now().plus(30, ChronoUnit.DAYS), within(60, ChronoUnit.SECONDS));
        assertThat(saved.getUserAgent()).isEqualTo("Mozilla/5.0");
        assertThat(saved.getIp()).isEqualTo("127.0.0.1");
        assertThat(saved.getCity()).isEqualTo("Москва");
    }

    @Test
    void createRefreshToken_withoutRememberMe_createsOneDayToken() {
        User user = user();
        when(refreshTokenRepository.save(org.mockito.ArgumentMatchers.any(RefreshToken.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        RefreshToken saved = refreshTokenService.createRefreshToken(user, false, null, null, null);

        assertThat(saved.isRememberMe()).isFalse();
        assertThat(saved.getExpiryDate())
                .isCloseTo(Instant.now().plus(1, ChronoUnit.DAYS), within(60, ChronoUnit.SECONDS));
    }
}