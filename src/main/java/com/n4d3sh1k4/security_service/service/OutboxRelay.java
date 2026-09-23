package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.security_service.domain.model.outbox.OutboxEvent;
import com.n4d3sh1k4.security_service.domain.repository.OutboxEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;

@Component
@RequiredArgsConstructor
@Slf4j
public class OutboxRelay {

    private static final String EXCHANGE = "user-exchange";

    private final OutboxEventRepository repository;
    private final RabbitTemplate rabbitTemplate;
    private final ObjectMapper objectMapper;

    @Scheduled(fixedDelay = 1000)
    @Transactional
    public void relay() {
        for (OutboxEvent event : repository.findTop100ByPublishedAtIsNullOrderByCreatedAtAsc()) {
            try {
                Object payload = objectMapper.readValue(
                        event.getPayload(),
                        Class.forName(event.getEventType()));
                rabbitTemplate.convertAndSend(EXCHANGE, event.getRoutingKey(), payload);
                event.setPublishedAt(Instant.now());
                repository.save(event);
            } catch (Exception e) {
                log.error("Outbox: failed to relay event {} ({}): {}",
                        event.getId(), event.getRoutingKey(), e.getMessage());
            }
        }
    }
}