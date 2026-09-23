package com.n4d3sh1k4.security_service.listener;

import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import com.n4d3sh1k4.security_service.dto.event.AccountLockedMessage;
import com.n4d3sh1k4.security_service.service.OutboxPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationFailureListener {

    @Value("${account.locked.cooldown}")
    String accountLockedCooldown;

    private final UserRepository userRepository;
    private final OutboxPublisher outboxPublisher;

    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
        String email = event.getAuthentication().getName();
        log.warn("Failed login attempt for user: {}", email);

        userRepository.findByEmail(email).ifPresent(user -> {
            if (user.isAccountNonLocked()) {
                user.setFailedAttempts(user.getFailedAttempts() + 1);

                if (user.getFailedAttempts() >= 5) {
                    lockUser(user);
                } else {
                    userRepository.save(user);
                }
            }
        });
    }

    private void lockUser(User user) {
        user.setAccountNonLocked(false);
        user.setLockTime(Instant.now().plus(Duration.ofMinutes(Long.parseLong(accountLockedCooldown))));
        userRepository.save(user);

        log.error("User {} is locked due to too many failed attempts", user.getEmail());

        outboxPublisher.publish("user.account.locked",
            new AccountLockedMessage(user.getEmail(), Instant.now(), accountLockedCooldown));
    }
}