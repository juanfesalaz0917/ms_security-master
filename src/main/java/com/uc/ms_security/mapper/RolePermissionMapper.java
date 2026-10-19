package com.uc.ms_security.mapper;

import com.uc.ms_security.dto.permission.PermissionResponseDTO;
import com.uc.ms_security.dto.role.RoleResponseDTO;
import com.uc.ms_security.dto.rolepermission.PermissionRoleResponseDTO;
import com.uc.ms_security.dto.rolepermission.RolePermissionResponseDTO;
import com.uc.ms_security.entity.Permission;
import com.uc.ms_security.entity.Role;
import com.uc.ms_security.entity.RolePermission;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class RolePermissionMapper {

    public RolePermissionResponseDTO toResponseDTO(RolePermission rolePermission) {
        Permission permission = rolePermission.getPermission();
        return new RolePermissionResponseDTO(
                rolePermission.getId(),
                rolePermission.getRole().getId(),
                new PermissionResponseDTO(
                        permission.getId(),
                        permission.getUrl(),
                        permission.getMethod(),
                        permission.getModel()
                )
        );
    }

    public List<RolePermissionResponseDTO> toResponseDTOList(List<RolePermission> rolePermissions) {
        return rolePermissions.stream()
                .map(this::toResponseDTO)
                .toList();
    }

    public PermissionRoleResponseDTO toPermissionRoleResponseDTO(RolePermission rolePermission) {
        Role role = rolePermission.getRole();
        return new PermissionRoleResponseDTO(
                rolePermission.getId(),
                rolePermission.getPermission().getId(),
                new RoleResponseDTO(
                        role.getId(),
                        role.getName(),
                        role.getDescription()
                )
        );
    }

    public List<PermissionRoleResponseDTO> toPermissionRoleResponseDTOList(
            List<RolePermission> rolePermissions) {
        return rolePermissions.stream()
                .map(this::toPermissionRoleResponseDTO)
                .toList();
    }
}
