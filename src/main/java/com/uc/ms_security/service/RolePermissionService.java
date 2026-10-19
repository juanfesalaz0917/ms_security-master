package com.uc.ms_security.service;

import com.uc.ms_security.dto.rolepermission.AssignPermissionRequestDTO;
import com.uc.ms_security.dto.rolepermission.PermissionRoleResponseDTO;
import com.uc.ms_security.dto.rolepermission.RolePermissionResponseDTO;
import com.uc.ms_security.entity.Permission;
import com.uc.ms_security.entity.Role;
import com.uc.ms_security.entity.RolePermission;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.mapper.RolePermissionMapper;
import com.uc.ms_security.repository.PermissionRepository;
import com.uc.ms_security.repository.RolePermissionRepository;
import com.uc.ms_security.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class RolePermissionService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final RolePermissionMapper rolePermissionMapper;

    public RolePermissionResponseDTO assign(AssignPermissionRequestDTO dto) {
        Role role = roleRepository.findById(dto.getRoleId())
                .orElseThrow(() -> new ApplicationException(
                        ErrorCase.NOT_FOUND,
                        "Rol no encontrado con id: " + dto.getRoleId()
                ));

        Permission permission = permissionRepository.findById(dto.getPermissionId())
                .orElseThrow(() -> new ApplicationException(
                        ErrorCase.NOT_FOUND,
                        "Permiso no encontrado con id: " + dto.getPermissionId()
                ));

        if (rolePermissionRepository.existsByRoleIdAndPermissionId(
                dto.getRoleId(), dto.getPermissionId())) {
            throw new ApplicationException(
                    ErrorCase.ALREADY_EXISTS,
                    "El rol ya tiene asignado ese permiso"
            );
        }

        RolePermission rolePermission = RolePermission.builder()
                .role(role)
                .permission(permission)
                .build();

        return rolePermissionMapper.toResponseDTO(
                rolePermissionRepository.save(rolePermission)
        );
    }

    @Transactional(readOnly = true)
    public List<RolePermissionResponseDTO> findAll() {
        return rolePermissionMapper.toResponseDTOList(rolePermissionRepository.findAll());
    }

    @Transactional(readOnly = true)
    public List<RolePermissionResponseDTO> findByRoleId(Long roleId) {
        if (!roleRepository.existsById(roleId)) {
            throw new ApplicationException(
                    ErrorCase.NOT_FOUND,
                    "Rol no encontrado con id: " + roleId
            );
        }
        return rolePermissionMapper.toResponseDTOList(
                rolePermissionRepository.findAllByRoleId(roleId)
        );
    }

    @Transactional(readOnly = true)
    public List<PermissionRoleResponseDTO> findByPermissionId(Long permissionId) {
        if (!permissionRepository.existsById(permissionId)) {
            throw new ApplicationException(
                    ErrorCase.NOT_FOUND,
                    "Permiso no encontrado con id: " + permissionId
            );
        }
        return rolePermissionMapper.toPermissionRoleResponseDTOList(
                rolePermissionRepository.findAllByPermissionId(permissionId)
        );
    }

    public void delete(Long roleId, Long permissionId) {
        RolePermission rolePermission = rolePermissionRepository
                .findByRoleIdAndPermissionId(roleId, permissionId)
                .orElseThrow(() -> new ApplicationException(
                        ErrorCase.NOT_FOUND,
                        "Asignación de permiso no encontrada para el rol "
                                + roleId + " y permiso " + permissionId
                ));

        rolePermissionRepository.delete(rolePermission);
    }
}
