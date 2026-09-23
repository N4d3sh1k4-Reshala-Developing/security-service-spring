package com.n4d3sh1k4.security_service.listener;

import com.n4d3sh1k4.security_service.dto.event.UserCreatedEvent;
import com.n4d3sh1k4.security_service.dto.event.UserRegisteredInternalEvent;
import com.n4d3sh1k4.security_service.service.OutboxPublisher;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@RequiredArgsConstructor
@Slf4j
public class UserRegistrationEventListener {

    private final OutboxPublisher outboxPublisher;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleUserRegistration(UserRegisteredInternalEvent event) {
        log.info("Transaction committed. Storing user.created event for user: {}", event.id());

        UserCreatedEvent rabbitEvent = new UserCreatedEvent(event.id(), event.firstName(), event.lastName(), event.email(), event.phone());

        outboxPublisher.publish("user.created", rabbitEvent);
    }
}
