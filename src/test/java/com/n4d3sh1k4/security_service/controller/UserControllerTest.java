package com.n4d3sh1k4.security_service.controller;

import com.n4d3sh1k4.security_service.jwt.JwtProvider;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.autoconfigure.web.DataWebAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(excludeAutoConfiguration = DataWebAutoConfiguration.class, properties = "app.test.webmvc-config=enabled")
@Import(UserController.class)
@AutoConfigureMockMvc(addFilters = true)
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtProvider jwtProvider;

    @Test
    void checkMe_authenticated_returnsAuthorities() throws Exception {
        mockMvc.perform(get("/users/check-me")
                        .with(user("550e8400-e29b-41d4-a716-446655440000").roles("USER")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("ROLE_USER")));
    }

    @Test
    void checkMe_admin_returnsAdminRole() throws Exception {
        mockMvc.perform(get("/users/check-me")
                        .with(user("550e8400-e29b-41d4-a716-446655440000").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("ROLE_ADMIN")));
    }
}