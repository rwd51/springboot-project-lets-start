package com.mlvu.mlvu_auth.config;

import com.mlvu.mlvu_auth.entity.ERole;
import com.mlvu.mlvu_auth.entity.Role;
import com.mlvu.mlvu_auth.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DatabaseInitializer implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public void run(String... args) throws Exception {
        initRoles();
    }

    private void initRoles() {
        // Initialize roles if they don't exist
        for (ERole role : ERole.values()) {
            if (!roleRepository.existsByName(role)) {
                Role newRole = new Role();
                newRole.setName(role);
                
                switch (role) {
                    case ROLE_USER:
                        newRole.setDescription("Standard user role");
                        break;
                    case ROLE_MODERATOR:
                        newRole.setDescription("Moderator role with elevated permissions");
                        break;
                    case ROLE_ADMIN:
                        newRole.setDescription("Administrator role with full permissions");
                        break;
                }
                
                roleRepository.save(newRole);
            }
        }
    }
}