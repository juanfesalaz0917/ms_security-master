package com.uc.ms_security.service;

import java.util.List;
import java.util.Locale;

import com.uc.ms_security.dto.permission.CreatePermissionDTO;
import com.uc.ms_security.dto.permission.PermissionResponseDTO;
import com.uc.ms_security.dto.permission.UpdatePermissionDTO;
import com.uc.ms_security.entity.Permission;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.mapper.PermissionMapper;
import com.uc.ms_security.repository.PermissionRepository;
import com.uc.ms_security.repository.RolePermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class PermissionService {

    private final PermissionRepository permissionRepository;
    private final RolePermissionRepository rolePermissionRepository;
    private final PermissionMapper permissionMapper;

    public PermissionResponseDTO create(CreatePermissionDTO dto) {
        String url = dto.getUrl();
        String method = dto.getMethod().toUpperCase();

        if (permissionRepository.existsByUrlAndMethod(url, method)) {
            throw new ApplicationException(
                    ErrorCase.ALREADY_EXISTS,
                    "Ya existe un permiso para la url y método indicados"
            );
        }

        Permission savedPermission = permissionRepository.save(permissionMapper.toEntity(dto));
        return permissionMapper.toResponseDTO(savedPermission);
    }

    @Transactional(readOnly = true)
    public List<PermissionResponseDTO> findAll() {
        return permissionMapper.toResponseDTOList(permissionRepository.findAll());
    }

    @Transactional(readOnly = true)
    public PermissionResponseDTO findById(Long id) {
        return permissionMapper.toResponseDTO(findPermission(id));
    }

    public PermissionResponseDTO update(Long id, UpdatePermissionDTO dto) {
        Permission permission = findPermission(id);
        String url = dto.getUrl();
        String method = dto.getMethod().toUpperCase();

        if (permissionRepository.existsByUrlAndMethodAndIdNot(url, method, id)) {
            throw new ApplicationException(
                    ErrorCase.ALREADY_EXISTS,
                    "La url y el método ya están registrados en otro permiso"
            );
        }

        permissionMapper.updateEntity(dto, permission);
        return permissionMapper.toResponseDTO(permissionRepository.save(permission));
    }

    public void delete(Long id) {
        Permission permission = findPermission(id);

        if (rolePermissionRepository.existsByPermissionId(id)) {
            throw new ApplicationException(
                    ErrorCase.INVALID_OPERATION,
                    "No se puede eliminar un permiso que está asignado a un rol"
            );
        }

        permissionRepository.delete(permission);
    }

    // Verificación que el usuario mediante su role tenga permiso para hacer alguna acción
    @Transactional(readOnly = true)
    public boolean hasPermission(
            Long userId,
            String httpMethod,
            String requestUrl) {

        if (userId == null || httpMethod == null || requestUrl == null) {
            return false;
        }

        String normalizedUrl = normalizeUrl(requestUrl);

        return permissionRepository
                .findByUserIdAndMethodAndUrl(
                        userId,
                        httpMethod.toUpperCase(Locale.ROOT),
                        normalizedUrl
                )
                .stream()
                .findAny()
                .isPresent();
    }


    private String normalizeUrl(String requestUrl) {
        return requestUrl.replaceAll(
                "(?i)(?<=/)(?:\\d+|[a-f0-9]{24})(?=/|$)",
                "{id}"
        );
    }

    private Permission findPermission(Long id) {
        return permissionRepository.findById(id)
                .orElseThrow(() -> new ApplicationException(
                        ErrorCase.NOT_FOUND,
                        "Permiso no encontrado con id: " + id
                ));
    }
}