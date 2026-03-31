package com.n4d3sh1k4.security_service.listener;

import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import com.n4d3sh1k4.security_service.dto.event.AccountLockedMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationFailureListener {

    private final UserRepository userRepository;
    private final RabbitTemplate rabbitTemplate;

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
        user.setLockTime(Instant.now().plus(Duration.ofMinutes(10)));
        userRepository.save(user);

        log.error("User {} is locked due to too many failed attempts", user.getEmail());

        rabbitTemplate.convertAndSend("user-exchange", "user.account.locked",
            new AccountLockedMessage(user.getEmail(), Instant.now()));
    }
}