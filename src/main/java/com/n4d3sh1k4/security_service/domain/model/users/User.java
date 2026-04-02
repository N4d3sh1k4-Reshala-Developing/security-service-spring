package com.n4d3sh1k4.security_service.domain.model.users;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.annotation.Nullable;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Collection;
import java.util.UUID;

@Entity
@Table(name = "users")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    private UUID id;

    @Column(name = "password_hash", nullable = true)
    private String passwordHash;

    @Column(name = "email")
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_provider")
    private AuthProvider provider = AuthProvider.LOCAL;

    @Column(name = "enabled")
    private Boolean enabled = false;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "users_roles", joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"), inverseJoinColumns = @JoinColumn(name = "role_id", referencedColumnName = "id"))
    @JsonIgnore
    private Collection<Role> roles;

    @Column(name = "failed_attempts")
    private int failedAttempts;

    @Column(name = "account_non_locked")
    private boolean accountNonLocked = true;

    @Column(name = "lock_time")
    private Instant lockTime;
}