package com.n4d3sh1k4.security_service.service;

import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import com.n4d3sh1k4.security_service.domain.model.users.Role;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.model.users.UserIdentity;
import com.n4d3sh1k4.security_service.domain.repository.RoleRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserIdentityRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import com.n4d3sh1k4.security_service.dto.event.PhoneBackfillEvent;
import com.n4d3sh1k4.security_service.dto.event.UserRegisteredInternalEvent;
import com.n4d3sh1k4.security_service.exception.OAuthEmailAlreadyExistsException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.context.ApplicationEventPublisher;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private ApplicationEventPublisher eventPublisher;

    @Mock
    private UserIdentityRepository userIdentityRepository;

    @Mock
    private OutboxPublisher outboxPublisher;

    @InjectMocks
    private UserService userService;

    @Test
    void processOAuthPostLogin_whenIdentityExists_returnsExistingUser() {
        User existing = new User();
        existing.setId(UUID.randomUUID());
        existing.setEmail("user@example.com");
        UserIdentity identity = new UserIdentity();
        identity.setUser(existing);
        identity.setProvider(AuthProvider.YANDEX);
        identity.setProviderUserId("ya-1");
        when(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.YANDEX, "ya-1"))
                .thenReturn(Optional.of(identity));

        User result = userService.processOAuthPostLogin(AuthProvider.YANDEX, "ya-1",
                "user@example.com", "Иван", "Петров", "+70000000000");

        assertThat(result).isSameAs(existing);
        verify(userRepository, never()).save(any(User.class));
        verify(eventPublisher, never()).publishEvent(any());
        verify(outboxPublisher).publish("user.phone.backfill", new PhoneBackfillEvent(existing.getId(), "+70000000000"));
    }

    @Test
    void processOAuthPostLogin_whenEmailAlreadyExists_throwsOAuthEmailAlreadyExists() {
        User existing = new User();
        existing.setId(UUID.randomUUID());
        existing.setEmail("user@example.com");
        when(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.YANDEX, "ya-1"))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> userService.processOAuthPostLogin(AuthProvider.YANDEX, "ya-1",
                "User@example.com", "Иван", "Петров", "+70000000000"))
                .isInstanceOf(OAuthEmailAlreadyExistsException.class)
                .satisfies(e -> {
                    assertThat(((OAuthEmailAlreadyExistsException) e).getEmail()).isEqualTo("User@example.com");
                    assertThat(((OAuthEmailAlreadyExistsException) e).getProvider()).isEqualTo(AuthProvider.YANDEX);
                    assertThat(((OAuthEmailAlreadyExistsException) e).getProviderUserId()).isEqualTo("ya-1");
                });
    }

    @Test
    void processOAuthPostLogin_whenNewUser_createsUserIdentityAndPublishesEvent() {
        when(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.YANDEX, "ya-1"))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.empty());
        when(roleRepository.findByName("USER")).thenReturn(List.of(new Role("USER")));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(UUID.randomUUID());
            return u;
        });

        User result = userService.processOAuthPostLogin(AuthProvider.YANDEX, "ya-1",
                "User@Example.com", "  Иван  ", "Петров", "+70000000000");

        assertThat(result.getEmail()).isEqualTo("user@example.com");
        assertThat(result.getUsername()).isEqualTo("Иван Петров");
        assertThat(result.getPasswordHash()).isNull();
        assertThat(result.getEnabled()).isTrue();
        assertThat(result.getRoles()).extracting(Role::getName).containsExactly("USER");

        ArgumentCaptor<UserIdentity> identityCaptor = ArgumentCaptor.forClass(UserIdentity.class);
        verify(userIdentityRepository).save(identityCaptor.capture());
        assertThat(identityCaptor.getValue().getUser()).isSameAs(result);
        assertThat(identityCaptor.getValue().getProvider()).isEqualTo(AuthProvider.YANDEX);
        assertThat(identityCaptor.getValue().getProviderUserId()).isEqualTo("ya-1");

        ArgumentCaptor<UserRegisteredInternalEvent> eventCaptor =
                ArgumentCaptor.forClass(UserRegisteredInternalEvent.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        UserRegisteredInternalEvent event = eventCaptor.getValue();
        assertThat(event.id()).isEqualTo(result.getId());
        assertThat(event.email()).isEqualTo("user@example.com");
        assertThat(event.phone()).isEqualTo("+70000000000");
    }

    @Test
    void processOAuthPostLogin_whenNamesBlank() {
        when(userIdentityRepository.findByProviderAndProviderUserId(AuthProvider.YANDEX, "ya-2"))
                .thenReturn(Optional.empty());
        when(userRepository.findByEmail("ivan@example.com")).thenReturn(Optional.empty());
        when(roleRepository.findByName("USER")).thenReturn(List.of(new Role("USER")));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            u.setId(UUID.randomUUID());
            return u;
        });

        User result = userService.processOAuthPostLogin(AuthProvider.YANDEX, "ya-2",
                "ivan@example.com", null, "", null);

        assertThat(result.getUsername()).isEqualTo("ivan");

        ArgumentCaptor<UserRegisteredInternalEvent> eventCaptor =
                ArgumentCaptor.forClass(UserRegisteredInternalEvent.class);
        verify(eventPublisher).publishEvent(eventCaptor.capture());
        UserRegisteredInternalEvent event = eventCaptor.getValue();
        assertThat(event.email()).isEqualTo("ivan@example.com");
    }
}