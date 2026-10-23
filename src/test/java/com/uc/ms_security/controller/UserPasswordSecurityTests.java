package com.uc.ms_security.controller;

import com.uc.ms_security.TestPermissionAssigner;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.repository.PermissionRepository;
import com.uc.ms_security.repository.RolePermissionRepository;
import com.uc.ms_security.repository.RoleRepository;
import com.uc.ms_security.repository.UserRoleRepository;
import com.uc.ms_security.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class UserPasswordSecurityTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private UserRoleRepository userRoleRepository;

    @Autowired
    private PermissionRepository permissionRepository;

    @Autowired
    private RolePermissionRepository rolePermissionRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void createHashesPasswordAndDoesNotReturnIt() throws Exception {
        String rawPassword = "ClaveSegura123!";
        String accessToken = obtainAccessToken();

        MvcResult result = mockMvc.perform(post("/api/users")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "name": "Ana Gómez",
                                  "email": "ana-bcrypt@example.com",
                                  "password": "ClaveSegura123!"
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist())
                .andReturn();

        JsonNode response = objectMapper.readTree(
                result.getResponse().getContentAsString()
        );
        assertThat(response.has("password")).isFalse();
        assertThat(response.has("passwordHash")).isFalse();

        User savedUser = userRepository.findByEmail("ana-bcrypt@example.com")
                .orElseThrow();
        assertThat(savedUser.getPassword()).isNotEqualTo(rawPassword);
        assertThat(savedUser.getPassword()).startsWith("$2");
        assertThat(passwordEncoder.matches(rawPassword, savedUser.getPassword()))
                .isTrue();
    }

    @Test
    void createRejectsPasswordThatDoesNotMeetRequirements() throws Exception {
        String accessToken = obtainAccessToken();

        mockMvc.perform(post("/api/users")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "name": "Ana Gómez",
                                  "email": "ana-invalid@example.com",
                                  "password": "clave123"
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").exists());

        assertThat(userRepository.findByEmail("ana-invalid@example.com"))
                .isEmpty();
    }

    @Test
    void createRejectsPasswordLongerThanBcryptUtf8Limit() throws Exception {
        String unicodePassword = "Aa1!" + "😀".repeat(34);
        String accessToken = obtainAccessToken();

        mockMvc.perform(post("/api/users")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "name": "Ana Gómez",
                                  "email": "ana-unicode@example.com",
                                  "password": "%s"
                                }
                                """.formatted(unicodePassword)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.password").exists());

        assertThat(userRepository.findByEmail("ana-unicode@example.com"))
                .isEmpty();
    }

    @Test
    void updateWithoutPasswordPreservesExistingHash() throws Exception {
        User user = createUser("ana-preserve@example.com", "ClaveSegura123!");
        String originalHash = user.getPassword();
        String accessToken = obtainAccessToken();

        mockMvc.perform(put("/api/users/{id}", user.getId())
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "name": "Ana Actualizada",
                                  "email": "ana-preserve@example.com"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.password").doesNotExist());

        User updatedUser = userRepository.findById(user.getId()).orElseThrow();
        assertThat(updatedUser.getPassword()).isEqualTo(originalHash);
        assertThat(passwordEncoder.matches(
                "ClaveSegura123!",
                updatedUser.getPassword()
        )).isTrue();
    }

    @Test
    void updateWithNewPasswordReplacesHash() throws Exception {
        User user = createUser("ana-update@example.com", "ClaveSegura123!");
        String originalHash = user.getPassword();
        String newPassword = "NuevaClave123!";
        String accessToken = obtainAccessToken();

        mockMvc.perform(put("/api/users/{id}", user.getId())
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "name": "Ana Actualizada",
                                  "email": "ana-update@example.com",
                                  "password": "NuevaClave123!"
                                }
                                """))
                .andExpect(status().isOk());

        User updatedUser = userRepository.findById(user.getId()).orElseThrow();
        assertThat(updatedUser.getPassword()).isNotEqualTo(originalHash);
        assertThat(passwordEncoder.matches(newPassword, updatedUser.getPassword()))
                .isTrue();
        assertThat(passwordEncoder.matches(
                "ClaveSegura123!",
                updatedUser.getPassword()
        )).isFalse();
    }

    @Test
    void userEndpointsRequireAuthentication()
            throws Exception {
        mockMvc.perform(get("/api/users"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer " + obtainAccessToken()))
                .andExpect(status().isOk());
    }

    private String obtainAccessToken() throws Exception {
        User user = createUser("password-tests@example.com", "LoginPassword123!");
        TestPermissionAssigner permissionAssigner = new TestPermissionAssigner(
                roleRepository,
                userRoleRepository,
                permissionRepository,
                rolePermissionRepository
        );
        permissionAssigner.grant(user, "GET", "/api/users");
        permissionAssigner.grant(user, "POST", "/api/users");
        permissionAssigner.grant(user, "PUT", "/api/users/{id}");

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "password-tests@example.com",
                                  "password": "LoginPassword123!"
                                }
                                """))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readTree(result.getResponse().getContentAsString())
                .get("accessToken")
                .asText();
    }

    private User createUser(String email, String rawPassword) {
        User user = new User();
        user.setName("Ana Gómez");
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(rawPassword));
        return userRepository.save(user);
    }
}
