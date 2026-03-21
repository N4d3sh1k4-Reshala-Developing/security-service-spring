package com.n4d3sh1k4.security_service.domain.model.security;

import com.n4d3sh1k4.security_service.domain.model.users.User;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "password_reset_tokens")
@Getter
@Setter
@NoArgsConstructor
public class PasswordResetToken {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    private String token;

    @OneToOne(fetch = FetchType.EAGER)
    private User user;

    private LocalDateTime expiryDate;

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiryDate);
    }
}
