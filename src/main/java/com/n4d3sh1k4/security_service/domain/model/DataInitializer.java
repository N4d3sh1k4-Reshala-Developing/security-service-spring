package com.n4d3sh1k4.security_service.domain.model;

import com.n4d3sh1k4.security_service.domain.model.users.Privilege;
import com.n4d3sh1k4.security_service.domain.model.users.Role;
import com.n4d3sh1k4.security_service.domain.repository.PrivilegeRepository;
import com.n4d3sh1k4.security_service.domain.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class DataInitializer implements CommandLineRunner {

    private final RoleRepository roleRepository;
    private final PrivilegeRepository privilegeRepository;

    @Override
    public void run(String... args) {

        if (roleRepository.count() == 0) {

            Privilege read = privilegeRepository.save(
                    new Privilege("USER_READ"));
            Privilege write = privilegeRepository.save(
                    new Privilege("USER_WRITE"));

            Role userRole = new Role("USER");
            userRole.setPrivileges(List.of(read, write));
            roleRepository.save(userRole);

            Role adminRole = new Role("ADMIN");
            adminRole.setPrivileges(List.of(read, write));
            roleRepository.save(adminRole);
        }
    }
}

