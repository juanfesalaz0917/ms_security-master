package com.uc.ms_security.mapper;

import java.util.List;

import com.uc.ms_security.dto.permission.CreatePermissionDTO;
import com.uc.ms_security.dto.permission.PermissionResponseDTO;
import com.uc.ms_security.dto.permission.UpdatePermissionDTO;
import com.uc.ms_security.entity.Permission;
import org.springframework.stereotype.Component;

@Component
public class PermissionMapper {

    public Permission toEntity(CreatePermissionDTO dto) {
        return Permission.builder()
                .url(dto.getUrl())
                .method(dto.getMethod().toUpperCase())
                .model(dto.getModel())
                .build();
    }

    public void updateEntity(UpdatePermissionDTO dto, Permission permission) {
        permission.setUrl(dto.getUrl());
        permission.setMethod(dto.getMethod().toUpperCase());

        if (dto.getModel() != null) {
            permission.setModel(dto.getModel());
        }
    }

    public PermissionResponseDTO toResponseDTO(Permission permission) {
        return new PermissionResponseDTO(
                permission.getId(),
                permission.getUrl(),
                permission.getMethod(),
                permission.getModel()
        );
    }

    public List<PermissionResponseDTO> toResponseDTOList(List<Permission> permissions) {
        return permissions.stream()
                .map(this::toResponseDTO)
                .toList();
    }
}