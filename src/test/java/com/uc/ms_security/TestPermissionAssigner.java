package com.uc.ms_security;

import com.uc.ms_security.entity.Permission;
import com.uc.ms_security.entity.Role;
import com.uc.ms_security.entity.RolePermission;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.entity.UserRole;
import com.uc.ms_security.repository.PermissionRepository;
import com.uc.ms_security.repository.RolePermissionRepository;
import com.uc.ms_security.repository.RoleRepository;
import com.uc.ms_security.repository.UserRoleRepository;

public final class TestPermissionAssigner {

    private final RoleRepository roleRepository;
    private final UserRoleRepository userRoleRepository;
    private final PermissionRepository permissionRepository;
    private final RolePermissionRepository rolePermissionRepository;

    public TestPermissionAssigner(
            RoleRepository roleRepository,
            UserRoleRepository userRoleRepository,
            PermissionRepository permissionRepository,
            RolePermissionRepository rolePermissionRepository) {
        this.roleRepository = roleRepository;
        this.userRoleRepository = userRoleRepository;
        this.permissionRepository = permissionRepository;
        this.rolePermissionRepository = rolePermissionRepository;
    }

    public void grant(User user, String method, String url) {
        Role role = roleRepository.findByNameIgnoreCase("TEST_AUTHORIZATION")
                .orElseGet(() -> {
                    Role newRole = new Role();
                    newRole.setName("TEST_AUTHORIZATION");
                    newRole.setDescription("Role used by authorization tests");
                    return roleRepository.save(newRole);
                });

        if (!userRoleRepository.existsByUserIdAndRoleId(user.getId(), role.getId())) {
            UserRole userRole = new UserRole();
            userRole.setUser(user);
            userRole.setRole(role);
            userRoleRepository.save(userRole);
        }

        Permission permission = permissionRepository.findByUrlAndMethod(url, method)
                .orElseGet(() -> {
                    Permission newPermission = new Permission();
                    newPermission.setUrl(url);
                    newPermission.setMethod(method);
                    return permissionRepository.save(newPermission);
                });

        if (!rolePermissionRepository.existsByRoleIdAndPermissionId(
                role.getId(),
                permission.getId())) {
            RolePermission rolePermission = new RolePermission();
            rolePermission.setRole(role);
            rolePermission.setPermission(permission);
            rolePermissionRepository.save(rolePermission);
        }
    }
}
