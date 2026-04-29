package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.common.exception.UserNotFoundException;
import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.repository.RoleRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import com.n4d3sh1k4.security_service.dto.event.NotificationEmailMessage;
import com.n4d3sh1k4.security_service.dto.request_dto.UserRequest;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final ApplicationEventPublisher eventPublisher;

    public UserRequest getUser(String userId) {
        return userRepository.findById(UUID.fromString(userId))
            .map(user -> new UserRequest(
                    user.getUsername(),
                    user.getEmail()
            ))
            .orElseThrow(() -> new UserNotFoundException(
                    "User with id " + userId + " not found"
            ));
    }

    @Transactional
    public User processOAuthPostLogin(String email, String firstName, String lastName) {
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

                newUser.setUsername(firstName+" "+lastName);

                userRepository.save(newUser);

                eventPublisher.publishEvent(new NotificationEmailMessage(
                        newUser.getEmail(),
                        firstName+" "+lastName,
                        null
                ));

                return newUser;
            });
    }
}