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


import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(excludeAutoConfiguration = DataWebAutoConfiguration.class, properties = "app.test.webmvc-config=enabled")
@Import(StatusController.class)
@AutoConfigureMockMvc(addFilters = true)
class StatusControllerTest {

    private static final String USER_ID = "550e8400-e29b-41d4-a716-446655440000";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtProvider jwtProvider;

    @Test
    void hello_authenticated_returnsHello() throws Exception {
        mockMvc.perform(get("/status/hello").with(user(USER_ID)))
                .andExpect(status().isOk())
                .andExpect(content().string("hello"));
    }

    @Test
    void me_returnsUserIdAndRoles() throws Exception {
        mockMvc.perform(get("/status/me").with(user(USER_ID).roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.userId").value(USER_ID))
                .andExpect(jsonPath("$.data.roles[0]").value("ROLE_ADMIN"))
                .andExpect(jsonPath("$.data.source").value("Gateway Headers"));
    }

    @Test
    void me_userRole_returnsUserRole() throws Exception {
        mockMvc.perform(get("/status/me").with(user(USER_ID).roles("USER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.roles[0]").value("ROLE_USER"));
    }
}