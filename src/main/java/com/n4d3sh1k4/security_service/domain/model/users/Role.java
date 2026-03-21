package com.n4d3sh1k4.security_service.domain.model.users;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Collection;
import java.util.UUID;

@Entity
@Table(name = "roles")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    private UUID id;

    @Column(unique = true)
    private String name;

    @ManyToMany(mappedBy = "roles")
    private Collection<User> users;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
        name = "roles_privileges",
        joinColumns = @JoinColumn(
          name = "role_id", referencedColumnName = "id"),
        inverseJoinColumns = @JoinColumn(
          name = "privilege_id", referencedColumnName = "id"))
    private Collection<Privilege> privileges;

    public Role(String roleUser) {
        this.name = roleUser;
    }
}
