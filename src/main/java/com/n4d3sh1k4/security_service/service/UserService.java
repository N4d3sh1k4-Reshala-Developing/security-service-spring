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
                .map(identity -> handleKnownIdentity(identity, email, phone))
                .orElseGet(() -> createUserFromProvider(provider, providerUserId, email, firstName, lastName, phone));
    }

    private User handleKnownIdentity(UserIdentity identity, String providerEmail, String phone) {
        User user = identity.getUser();
        if (phone != null && !phone.isBlank()) {
            outboxPublisher.publish("user.phone.backfill", new PhoneBackfillEvent(user.getId(), phone));
        }
        syncEmailFromProvider(user, identity.getProvider(), providerEmail);
        return user;
    }

    /**
     * Почту в аккаунте синхронизируем с провайдером только у пользователей, созданных через OAuth
     * (пароля нет, значит почта провайдера — единственный источник входа). Для аккаунтов с паролем
     * почта принадлежит пользователю, поэтому расхождение только логируется.
     */
    private void syncEmailFromProvider(User user, AuthProvider provider, String providerEmail) {
        if (providerEmail == null || providerEmail.isBlank()) {
            return;
        }
        String normalized = providerEmail.toLowerCase();
        if (normalized.equals(user.getEmail())) {
            return;
        }
        if (user.getPasswordHash() != null) {
            log.warn("Provider {} email changed for userId={}: stored={}, provider={}. Not synced because the account has a password.",
                    provider, user.getId(), user.getEmail(), normalized);
            return;
        }
        if (userRepository.findByEmail(normalized).isPresent()) {
            log.warn("Provider {} email changed for userId={} to {}, but that email is already taken. Not synced.",
                    provider, user.getId(), normalized);
            return;
        }
        log.info("Syncing email from provider {} for userId={}: {} -> {}",
                provider, user.getId(), user.getEmail(), normalized);
        user.setEmail(normalized);
        userRepository.save(user);
    }

    private User createUserFromProvider(AuthProvider provider, String providerUserId, String email, String firstName, String lastName, String phone) {
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
        newUser.setProvider(provider);
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
    }
}