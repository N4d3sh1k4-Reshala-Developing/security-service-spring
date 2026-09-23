package com.n4d3sh1k4.security_service.listener;

import com.n4d3sh1k4.security_service.dto.event.NotificationEmailEvent;
import com.n4d3sh1k4.security_service.dto.event.NotificationEmailMessage;
import com.n4d3sh1k4.security_service.service.OutboxPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@RequiredArgsConstructor
@Slf4j
public class UserResendEmailInternalEventListener {

    private final OutboxPublisher outboxPublisher;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleUserRegistration(NotificationEmailEvent event) {
        log.info("Transaction registered. Storing user.registration.email event for user: {}", event.email());

        NotificationEmailMessage rabbitEvent = new NotificationEmailMessage(event.email(), event.username(), event.token(), event.accountActivationTokenTtl());

        outboxPublisher.publish("user.registration.email", rabbitEvent);
    }
}
