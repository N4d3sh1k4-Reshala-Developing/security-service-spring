package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.repository.RoleRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import com.n4d3sh1k4.security_service.dto.event.UserRegisteredInternalEvent;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final ApplicationEventPublisher eventPublisher;

    @Transactional
    public User processOAuthPostLogin(String email, String fullName) {
        return userRepository.findByEmail(email)
            .map(user -> {
                log.info("OAuth login for existing user: {}", email);
                return user;
            })
            .orElseGet(() -> {
                log.info("Creating new user via Yandex OAuth: {}", email);

                User newUser = new User();
                newUser.setEmail(email);
                newUser.setPasswordHash(null);

                newUser.setEnabled(true);
                newUser.setAccountNonLocked(true);

                newUser.setProvider(AuthProvider.YANDEX);
                newUser.setRoles(roleRepository.findByName("USER"));
                userRepository.save(newUser);

                eventPublisher.publishEvent(new UserRegisteredInternalEvent(
                        newUser.getId(),
                        fullName,
                        newUser.getEmail()
                ));

                return newUser;
            });
    }
}