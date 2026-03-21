package com.n4d3sh1k4.security_service.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class JwtResponse {
    private final String type = "Bearer";
    private String accessToken;
}
