package com.n4d3sh1k4.security_service.listener;

import com.n4d3sh1k4.security_service.dto.event.PasswordResetEvent;
import com.n4d3sh1k4.security_service.dto.event.PasswordResetMessage;
import com.n4d3sh1k4.security_service.service.OutboxPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@RequiredArgsConstructor
@Slf4j
public class PasswordResetEventListener {

    private final OutboxPublisher outboxPublisher;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handlePasswordReset(PasswordResetEvent event) {
        log.info("Transaction registered. Storing user.password.reset event for user: {}", event.email());

        PasswordResetMessage message = new PasswordResetMessage(event.email(), event.token(), event.passwordResetTokenTtl());

        outboxPublisher.publish("user.password.reset", message);
    }
}
