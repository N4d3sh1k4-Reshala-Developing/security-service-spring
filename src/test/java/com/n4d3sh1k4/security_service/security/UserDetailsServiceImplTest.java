package com.n4d3sh1k4.security_service.security;

import com.n4d3sh1k4.security_service.domain.model.users.Role;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserDetailsServiceImplTest {

    private static final String EMAIL = "oauth-user@example.com";

    @Mock
    private UserRepository userRepository;

    private PasswordEncoder passwordEncoder;
    private UserDetailsServiceImpl userDetailsService;

    @BeforeEach
    void setUp() {
        passwordEncoder = new Argon2PasswordEncoder(16, 32, 1, 65536, 3);
        userDetailsService = new UserDetailsServiceImpl(userRepository, passwordEncoder);
    }

    @Test
    void loadUserByUsername_whenUserNotFound_throwsUsernameNotFound() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userDetailsService.loadUserByUsername(EMAIL))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void loadUserByUsername_whenPasswordHashMissing_passwordCheckFailsWithoutException() {
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(oauthUser(null)));

        UserDetails details = userDetailsService.loadUserByUsername(EMAIL);

        assertThatCode(() -> passwordEncoder.matches("Password#4848", details.getPassword()))
                .doesNotThrowAnyException();
        assertThat(passwordEncoder.matches("Password#4848", details.getPassword())).isFalse();
    }

    @Test
    void loadUserByUsername_whenPasswordHashPresent_passwordCheckWorks() {
        String hash = passwordEncoder.encode("Password#4848");
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(oauthUser(hash)));

        UserDetails details = userDetailsService.loadUserByUsername(EMAIL);

        assertThat(details.getPassword()).isEqualTo(hash);
        assertThat(passwordEncoder.matches("Password#4848", details.getPassword())).isTrue();
    }

    @Test
    void loadUserByUsername_whenEnabledIsNull_userIsDisabled() {
        User user = oauthUser("hash");
        user.setEnabled(null);
        when(userRepository.findByEmail(EMAIL)).thenReturn(Optional.of(user));

        UserDetails details = userDetailsService.loadUserByUsername(EMAIL);

        assertThat(details.isEnabled()).isFalse();
    }

    private User oauthUser(String passwordHash) {
        User user = new User();
        user.setEmail(EMAIL);
        user.setPasswordHash(passwordHash);
        user.setEnabled(true);
        user.setRoles(List.of(new Role("USER")));
        return user;
    }
}
