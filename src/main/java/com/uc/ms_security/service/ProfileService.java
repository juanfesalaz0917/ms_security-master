package com.uc.ms_security.service;

import com.uc.ms_security.dto.profile.ProfileRequestDTO;
import com.uc.ms_security.dto.profile.ProfileResponseDTO;
import com.uc.ms_security.entity.Profile;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.exception.ApplicationException;
import com.uc.ms_security.exception.ErrorCase;
import com.uc.ms_security.mapper.ProfileMapper;
import com.uc.ms_security.repository.ProfileRepository;
import com.uc.ms_security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class ProfileService {

    private final ProfileRepository profileRepository;

    private final UserRepository userRepository;

    private final ProfileMapper profileMapper;

    public ProfileResponseDTO create(Long userId, ProfileRequestDTO dto) {
        User user = findUser(userId);

        if (profileRepository.existsByUserId(user.getId())) {
                throw new ApplicationException(
                    ErrorCase.ALREADY_EXISTS,
                    "El usuario ya tiene un perfil registrado"
            );
        }

        Profile profile = profileMapper.toEntity(dto);
        profile.setUser(user);
        Profile savedProfile = profileRepository.save(profile);

        return profileMapper.toResponseDTO(savedProfile);
    }

    @Transactional
    public ProfileResponseDTO findByUserId(Long userId) {
        Profile profile = profileRepository.findByUserId(userId)
                .orElseThrow(() -> new ApplicationException(
                    ErrorCase.NOT_FOUND,
                    "Perfil del usuario no encontrado con id: " + userId
                ));

        return profileMapper.toResponseDTO(profile);
    }

    public ProfileResponseDTO update(Long userId, ProfileRequestDTO dto) {
        Profile profile = findProfile(userId);
        profileMapper.updateEntity(dto, profile);

        return profileMapper.toResponseDTO(profileRepository.save(profile));
    }

    public void delete(Long userId) {
        profileRepository.delete(findProfile(userId));
    }

    private Profile findProfile(Long id) {
        return profileRepository.findByUserId(id)
                .orElseThrow(() -> new ApplicationException(
                    ErrorCase.NOT_FOUND,
                    "Perfil no encontrado con id: " + id
                ));
    }

    private User findUser(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ApplicationException(
                    ErrorCase.NOT_FOUND,
                    "Usuario no encontrado con id: " + id
                ));
    }
}