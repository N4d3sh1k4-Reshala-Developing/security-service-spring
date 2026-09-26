package com.n4d3sh1k4.security_service.dto;

import java.util.List;

public record UserData(String username, String email, List<UserIdentityDto> identities) {
    public record UserIdentityDto(String id, String provider, String providerUserId, String createdAt) {
    }
}
