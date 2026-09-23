package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.security_service.domain.model.outbox.OutboxEvent;
import com.n4d3sh1k4.security_service.domain.repository.OutboxEventRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OutboxPublisherTest {

    @Mock
    private OutboxEventRepository repository;

    @Mock
    private ObjectMapper objectMapper;

    @InjectMocks
    private OutboxPublisher outboxPublisher;

    @Test
    void publish_serializesAndStoresOutboxRecord() {
        Map<String, String> event = Map.of("email", "user@example.com");
        when(objectMapper.writeValueAsString(event)).thenReturn("{\"email\":\"user@example.com\"}");

        outboxPublisher.publish("user.email.confirmed", event);

        ArgumentCaptor<OutboxEvent> captor = ArgumentCaptor.forClass(OutboxEvent.class);
        verify(repository).save(captor.capture());
        OutboxEvent record = captor.getValue();
        assertThat(record.getRoutingKey()).isEqualTo("user.email.confirmed");
        assertThat(record.getEventType()).isEqualTo(event.getClass().getName());
        assertThat(record.getPayload()).isEqualTo("{\"email\":\"user@example.com\"}");
        assertThat(record.getCreatedAt()).isNotNull();
    }

    @Test
    void publish_whenSerializationFails_throwsError() {
        when(objectMapper.writeValueAsString(any())).thenThrow(new JacksonException("boom") {});

        assertThatThrownBy(() -> outboxPublisher.publish("user.login.email", new Object()))
                .isInstanceOf(Error.class)
                .hasMessage("Failed to serialize outbox event");

        verify(repository, org.mockito.Mockito.never()).save(any(OutboxEvent.class));
    }
}