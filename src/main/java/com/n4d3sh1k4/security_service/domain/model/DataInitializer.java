package com.n4d3sh1k4.security_service.domain.model;

import com.n4d3sh1k4.security_service.domain.model.users.AuthProvider;
import com.n4d3sh1k4.security_service.domain.model.users.Privilege;
import com.n4d3sh1k4.security_service.domain.model.users.Role;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import com.n4d3sh1k4.security_service.domain.repository.PrivilegeRepository;
import com.n4d3sh1k4.security_service.domain.repository.RoleRepository;
import com.n4d3sh1k4.security_service.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final PrivilegeRepository privilegeRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder; // Из Spring Security для хэширования

    @Value("${app.default-admin.email}")
    private String adminEmail;

    @Value("${app.default-admin.password}")
    private String adminPassword;

    @Override
    public void run(String @NonNull ... args) {

        if (roleRepository.count() == 0) {

            Privilege read = privilegeRepository.save(new Privilege("USER_READ"));
            Privilege write = privilegeRepository.save(new Privilege("USER_WRITE"));

            Role userRole = new Role("USER");
            userRole.setPrivileges(List.of(read, write));
            roleRepository.save(userRole);

            Role adminRole = new Role("ADMIN");
            adminRole.setPrivileges(List.of(read, write));
            adminRole = roleRepository.save(adminRole);

            User admin = new User();
            admin.setEmail(adminEmail);
            admin.setPasswordHash(passwordEncoder.encode(adminPassword));
            admin.setProvider(AuthProvider.LOCAL);
            admin.setEnabled(true);
            admin.setAccountNonLocked(true);
            admin.setRoles(List.of(adminRole));

            userRepository.save(admin);
        }
    }
}