package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.model.users.UserIdentity;
import com.n4d3sh1k4.security_service.domain.repository.RoleRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserIdentityRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import com.n4d3sh1k4.security_service.dto.event.PhoneBackfillEvent;
import com.n4d3sh1k4.security_service.dto.event.UserRegisteredInternalEvent;
import com.n4d3sh1k4.security_service.exception.OAuthEmailAlreadyExistsException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final ApplicationEventPublisher eventPublisher;
    private final UserIdentityRepository userIdentityRepository;
    private final OutboxPublisher outboxPublisher;

    @Transactional
    public User processOAuthPostLogin(AuthProvider provider, String providerUserId, String email, String firstName, String lastName, String phone) {
        return userIdentityRepository.findByProviderAndProviderUserId(provider, providerUserId)
                .map(identity -> {
                    User user = identity.getUser();
                    if (phone != null && !phone.isBlank()) {
                        outboxPublisher.publish("user.phone.backfill", new PhoneBackfillEvent(user.getId(), phone));
                    }
                    return user;
                })
                .orElseGet(() -> {
                    if (userRepository.findByEmail(email.toLowerCase()).isPresent()) {
                        throw new OAuthEmailAlreadyExistsException(email, provider, providerUserId);
                    }

                    User newUser = new User();
                    String localEmail = email.toLowerCase();
                    String namePart = ((firstName == null ? "" : firstName.trim())
                            + " " + (lastName == null ? "" : lastName.trim())).trim();
                    newUser.setEmail(localEmail);
                    newUser.setUsername(namePart.isEmpty() ? localEmail.split("@", 2)[0] : namePart);
                    newUser.setPasswordHash(null);
                    newUser.setEnabled(true);
                    newUser.setRoles(roleRepository.findByName("USER"));
                    userRepository.save(newUser);

                    UserIdentity identity = new UserIdentity();
                    identity.setUser(newUser);
                    identity.setProvider(provider);
                    identity.setProviderUserId(providerUserId);
                    userIdentityRepository.save(identity);

                    eventPublisher.publishEvent(new UserRegisteredInternalEvent(
                            newUser.getId(),
                            newUser.getEmail(),
                            phone
                    ));
                    return newUser;
                });
    }
}