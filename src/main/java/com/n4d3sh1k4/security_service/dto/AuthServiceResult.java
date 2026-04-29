package com.n4d3sh1k4.security_service.dto;

import lombok.Data;

@Data
public class AuthServiceResult {
    private String accessToken;
    private String cookie;

    public AuthServiceResult(String accesToken, String cookie) {
        this.accessToken = accesToken;
        this.cookie = cookie;
    }

    public AuthServiceResult(String cookie) {
        this.cookie = cookie;
    }
}
