package com.n4d3sh1k4.security_service.domain.model.users;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Collection;
import java.util.UUID;

@Entity
@Table(name = "privilege")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Privilege {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "id")
    private UUID id;

    @Column(unique = true)
    private String name;

    @ManyToMany(mappedBy = "privileges")
    private Collection<Role> roles;

    public Privilege(String name) {
        this.name = name;
    }
}