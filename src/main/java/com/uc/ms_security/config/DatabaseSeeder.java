package com.uc.ms_security.config;

import com.uc.ms_security.entity.Permission;
import com.uc.ms_security.entity.Role;
import com.uc.ms_security.entity.RolePermission;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.entity.UserRole;
import com.uc.ms_security.repository.PermissionRepository;
import com.uc.ms_security.repository.RolePermissionRepository;
import com.uc.ms_security.repository.RoleRepository;
import com.uc.ms_security.repository.UserRepository;
import com.uc.ms_security.repository.UserRoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Component
@RequiredArgsConstructor
public class DatabaseSeeder implements CommandLineRunner {

    private static final List<PermissionSeed> ADMIN_PERMISSIONS = List.of(
            new PermissionSeed("GET", "/api/users"),
            new PermissionSeed("POST", "/api/users"),
            new PermissionSeed("GET", "/api/users/{id}"),
            new PermissionSeed("PUT", "/api/users/{id}"),
            new PermissionSeed("DELETE", "/api/users/{id}"),
            new PermissionSeed("GET", "/api/roles"),
            new PermissionSeed("POST", "/api/roles"),
            new PermissionSeed("GET", "/api/roles/{id}"),
            new PermissionSeed("PUT", "/api/roles/{id}"),
            new PermissionSeed("DELETE", "/api/roles/{id}"),
            new PermissionSeed("GET", "/api/permissions"),
            new PermissionSeed("POST", "/api/permissions"),
            new PermissionSeed("GET", "/api/permissions/{id}"),
            new PermissionSeed("PUT", "/api/permissions/{id}"),
            new PermissionSeed("DELETE", "/api/permissions/{id}")
    );

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRoleRepository userRoleRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final PasswordEncoder passwordEncoder;
    private final Environment environment;

    @Override
    @Transactional
    public void run(String... args) {
        Role adminRole = findOrCreateRole("ADMIN", "Administrador");
        Role consultantRole = findOrCreateRole(
                "CONSULTOR",
                "Consulta de usuarios"
        );

        for (PermissionSeed seed : ADMIN_PERMISSIONS) {
            assignPermission(adminRole, findOrCreatePermission(seed));
        }

        Permission listUsers = findOrCreatePermission(
                new PermissionSeed("GET", "/api/users")
        );
        Permission findUser = findOrCreatePermission(
                new PermissionSeed("GET", "/api/users/{id}")
        );
        assignPermission(consultantRole, listUsers);
        assignPermission(consultantRole, findUser);

        seedAdminUser(adminRole);
    }

    private Role findOrCreateRole(String name, String description) {
        return roleRepository.findByNameIgnoreCase(name)
                .orElseGet(() -> {
                    Role role = new Role();
                    role.setName(name);
                    role.setDescription(description);
                    return roleRepository.save(role);
                });
    }

    private Permission findOrCreatePermission(PermissionSeed seed) {
        return permissionRepository.findByUrlAndMethod(seed.url(), seed.method())
                .orElseGet(() -> {
                    Permission permission = new Permission();
                    permission.setUrl(seed.url());
                    permission.setMethod(seed.method());
                    return permissionRepository.save(permission);
                });
    }

    private void assignPermission(Role role, Permission permission) {
        if (!rolePermissionRepository.existsByRoleIdAndPermissionId(
                role.getId(),
                permission.getId())) {
            RolePermission assignment = new RolePermission();
            assignment.setRole(role);
            assignment.setPermission(permission);
            rolePermissionRepository.save(assignment);
        }
    }

    private void seedAdminUser(Role adminRole) {
        String email = environment.getProperty("security.seed.admin-email", "").trim();
        String rawPassword = environment.getProperty(
                "security.seed.admin-password",
                ""
        );

        if (email.isEmpty() && rawPassword.isEmpty()) {
            return;
        }
        if (email.isEmpty() || rawPassword.isBlank()) {
            throw new IllegalStateException(
                    "Configure tanto security.seed.admin-email como "
                            + "security.seed.admin-password para crear el usuario inicial"
            );
        }

        User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setName("Administrador");
                    newUser.setEmail(email);
                    newUser.setPassword(passwordEncoder.encode(rawPassword));
                    return userRepository.save(newUser);
                });

        if (!userRoleRepository.existsByUserIdAndRoleId(
                user.getId(),
                adminRole.getId())) {
            UserRole assignment = new UserRole();
            assignment.setUser(user);
            assignment.setRole(adminRole);
            userRoleRepository.save(assignment);
        }
    }

    private record PermissionSeed(String method, String url) {
    }
}
