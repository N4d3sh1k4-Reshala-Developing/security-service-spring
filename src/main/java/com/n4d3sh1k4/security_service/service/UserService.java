package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.common.exception.UserNotFoundException;
import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.repository.RoleRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserIdentityRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import com.n4d3sh1k4.security_service.domain.model.users.UserIdentity;
import com.n4d3sh1k4.security_service.dto.event.NotificationEmailEvent;
import com.n4d3sh1k4.security_service.dto.event.NotificationEmailMessage;
import com.n4d3sh1k4.security_service.dto.request_dto.UserRequest;
import com.n4d3sh1k4.security_service.exception.OAuthEmailAlreadyExistsException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.Map;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final UserIdentityRepository userIdentityRepository;

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
    public User processOAuthPostLogin(AuthProvider provider, String providerUserId, String email, String firstName, String lastName) {
        return userIdentityRepository.findByProviderAndProviderUserId(provider, providerUserId)
                .map(identity -> {
                    log.info("OAuth login for existing identity: {} - {}", provider, providerUserId);
                    return identity.getUser();
                })
                .orElseGet(() -> {
                    java.util.Optional<User> existingUserOpt = userRepository.findByEmail(email.toLowerCase());
                    if (existingUserOpt.isPresent()) {
                        log.warn("OAuth login failed: Email {} already exists, but no identity found for {} - {}", email, provider, providerUserId);
                        throw new OAuthEmailAlreadyExistsException(email, provider, providerUserId);
                    }

                    log.info("Creating new user via OAuth: {}", email);
                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setPasswordHash(null);
                    newUser.setEnabled(true);
                    newUser.setAccountNonLocked(true);
                    newUser.setProvider(provider);
                    newUser.setRoles(roleRepository.findByName("USER"));

                    String displayName;
                    boolean hasFirstName = firstName != null && !firstName.isBlank();
                    boolean hasLastName = lastName != null && !lastName.isBlank();
                    if (hasFirstName || hasLastName) {
                        displayName = ( (hasFirstName ? firstName : "") + " " + (hasLastName ? lastName : "") ).trim();
                    } else {
                        displayName = email.split("@")[0];
                    }
                    newUser.setUsername(displayName);
                    userRepository.save(newUser);

                    eventPublisher.publishEvent(new NotificationEmailEvent(
                            newUser.getEmail(),
                            displayName,
                            null
                    ));

                    log.info("Linking new OAuth identity {} - {} to new user {}", provider, providerUserId, newUser.getEmail());
                    UserIdentity identity = new UserIdentity();
                    identity.setUser(newUser);
                    identity.setProvider(provider);
                    identity.setProviderUserId(providerUserId);
                    userIdentityRepository.save(identity);

                    return newUser;
                });
    }
}