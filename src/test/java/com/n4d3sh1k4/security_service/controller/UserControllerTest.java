package com.n4d3sh1k4.security_service.controller;

import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.model.users.UserIdentity;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import com.n4d3sh1k4.security_service.jwt.JwtProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.autoconfigure.web.DataWebAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(excludeAutoConfiguration = DataWebAutoConfiguration.class, properties = "app.test.webmvc-config=enabled")
@Import(UserController.class)
@AutoConfigureMockMvc(addFilters = true)
class UserControllerTest {

    private static final String USER_ID = "550e8400-e29b-41d4-a716-446655440000";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtProvider jwtProvider;

    @MockitoBean
    private UserRepository userRepository;

    @Test
    void checkMe_authenticated_returnsAuthorities() throws Exception {
        mockMvc.perform(get("/user/check-me")
                        .with(user(USER_ID).roles("USER")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("ROLE_USER")));
    }

    @Test
    void checkMe_admin_returnsAdminRole() throws Exception {
        mockMvc.perform(get("/user/check-me")
                        .with(user(USER_ID).roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("ROLE_ADMIN")));
    }

    @Test
    void getUser_returnsUsernameEmailIdentities() throws Exception {
        User user = new User();
        user.setId(UUID.fromString(USER_ID));
        user.setUsername("misha5555548");
        user.setEmail("misha5555548@yandex.ru");

        UserIdentity identity = new UserIdentity();
        identity.setId(UUID.fromString("650e8400-e29b-41d4-a716-446655440000"));
        identity.setProvider(AuthProvider.YANDEX);
        identity.setProviderUserId("yandex-42");
        identity.setCreatedAt(Instant.parse("2026-01-01T00:00:00Z"));
        user.getIdentities().add(identity);

        when(userRepository.findById(UUID.fromString(USER_ID))).thenReturn(Optional.of(user));

        mockMvc.perform(get("/user").with(user(USER_ID).roles("USER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.username").value("misha5555548"))
                .andExpect(jsonPath("$.data.email").value("misha5555548@yandex.ru"))
                .andExpect(jsonPath("$.data.identities[0].id").value("650e8400-e29b-41d4-a716-446655440000"))
                .andExpect(jsonPath("$.data.identities[0].provider").value("YANDEX"))
                .andExpect(jsonPath("$.data.identities[0].providerUserId").value("yandex-42"))
                .andExpect(jsonPath("$.data.identities[0].createdAt").value("2026-01-01T00:00:00Z"));
    }

    @Test
    void getUser_withoutIdentities_returnsEmptyList() throws Exception {
        User user = new User();
        user.setId(UUID.fromString(USER_ID));
        user.setUsername("misha5555548");
        user.setEmail("misha5555548@yandex.ru");

        when(userRepository.findById(UUID.fromString(USER_ID))).thenReturn(Optional.of(user));

        mockMvc.perform(get("/user").with(user(USER_ID)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.identities").isArray())
                .andExpect(jsonPath("$.data.identities").isEmpty());
    }

    @Test
    void getUser_unknownUser_returns404() throws Exception {
        when(userRepository.findById(UUID.fromString(USER_ID))).thenReturn(Optional.empty());

        mockMvc.perform(get("/user").with(user(USER_ID)))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error.code").value("USER_NOT_FOUND"));
    }
}
