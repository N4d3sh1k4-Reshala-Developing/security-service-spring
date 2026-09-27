package com.n4d3sh1k4.security_service.security;

import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.UUID;
import java.util.stream.Collectors;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final String passwordlessUserHash;

    public UserDetailsServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordlessUserHash = passwordEncoder.encode(UUID.randomUUID().toString());
    }

    @Override
    public @NonNull UserDetails loadUserByUsername(@NonNull String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

        // У юзеров, созданных только через OAuth, пароля нет. Раньше подставлялся псевдо-хэш
        // "{noop}[OAUTH2_USER_WITHOUT_PASSWORD]", который PasswordEncoder (Argon2) не понимает:
        // matches() бросал IllegalArgumentException и запрос падал в 500. Теперь подставляется
        // валидный хэш неизвестного рандома — проверка пароля всегда проваливается штатно (401).
        String password = user.getPasswordHash() != null ? user.getPasswordHash() : passwordlessUserHash;

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(password)
                .authorities(user.getRoles().stream()
                        .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName()))
                        .collect(Collectors.toList()))
                .disabled(!Boolean.TRUE.equals(user.getEnabled()))
                .build();
    }
}