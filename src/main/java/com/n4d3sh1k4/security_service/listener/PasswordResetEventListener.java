package com.n4d3sh1k4.security_service.listener;

import com.n4d3sh1k4.security_service.dto.event.PasswordResetEvent;
import com.n4d3sh1k4.security_service.dto.event.PasswordResetMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@RequiredArgsConstructor
@Slf4j
public class PasswordResetEventListener {

    private final RabbitTemplate rabbitTemplate;

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handlePasswordReset(PasswordResetEvent event) {
        log.info("Transaction committed. Sending event to RabbitMQ for user: {}", event.email());

        PasswordResetMessage message = new PasswordResetMessage(event.email(), event.token());

        rabbitTemplate.convertAndSend("user-exchange", "user.password.reset", message);
    }
}
