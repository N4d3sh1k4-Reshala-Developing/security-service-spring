package com.n4d3sh1k4.security_service.listener;

import com.n4d3sh1k4.security_service.dto.event.NotificationEmailEvent;
import com.n4d3sh1k4.security_service.dto.event.NotificationEmailMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@RequiredArgsConstructor
@Slf4j
public class UserResendEmailInternalEventListener {

    private final RabbitTemplate rabbitTemplate;

    //фаза AFTER_COMMIT
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handleUserRegistration(NotificationEmailEvent event) {
        log.info("Transaction committed. Sending event to RabbitMQ for user: {}", event.email());

        NotificationEmailMessage rabbitEvent = new NotificationEmailMessage(event.email(), event.username(), event.token());

        rabbitTemplate.convertAndSend("user-exchange", "user.registration.email", rabbitEvent);
    }
}
