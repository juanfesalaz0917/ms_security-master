package com.uc.ms_security.controller;

import com.uc.ms_security.TestPermissionAssigner;
import com.uc.ms_security.entity.User;
import com.uc.ms_security.repository.PermissionRepository;
import com.uc.ms_security.repository.RolePermissionRepository;
import com.uc.ms_security.repository.RoleRepository;
import com.uc.ms_security.repository.UserRepository;
import com.uc.ms_security.repository.UserRoleRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class DynamicAuthorizationTests {

    @Autowired
    private MockMvc mockMvc;

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

    @Autowired
    private JwtEncoder jwtEncoder;

    @Test
    void validTokenWithoutPermissionIsForbidden() throws Exception {
        User user = createUser();

        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer " + tokenFor(user.getId())))
                .andExpect(status().isForbidden());
    }

    @Test
    void permissionMustMatchHttpMethod() throws Exception {
        User user = createUser();
        grant(user, "GET", "/api/users");

        mockMvc.perform(post("/api/users")
                        .header("Authorization", "Bearer " + tokenFor(user.getId()))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void numericAndMongoObjectIdsMatchTheIdPattern() throws Exception {
        User user = createUser();
        grant(user, "GET", "/api/users/{id}");
        grant(user, "GET", "/api/users/{id}/detail");
        String token = tokenFor(user.getId());

        mockMvc.perform(get("/api/users/987654321")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isNotFound());

        mockMvc.perform(get("/api/users/987654321/detail")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isNotFound());

        mockMvc.perform(get("/api/users/507f1f77bcf86cd799439011")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isBadRequest());
    }

    @Test
    void permissionChangesAreAppliedOnTheNextRequest() throws Exception {
        User user = createUser();
        grant(user, "GET", "/api/users");
        String token = tokenFor(user.getId());

        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        rolePermissionRepository.deleteAll(
                rolePermissionRepository.findAllByRoleId(
                        roleRepository.findByNameIgnoreCase("TEST_AUTHORIZATION")
                                .orElseThrow()
                                .getId()
                )
        );

        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void nonNumericSubjectIsDenied() throws Exception {
        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer " + tokenFor("not-a-user-id")))
                .andExpect(status().isForbidden());
    }

    private User createUser() {
        User user = new User();
        user.setName("Dynamic Authorization Test");
        user.setEmail(UUID.randomUUID() + "@example.com");
        user.setPassword(passwordEncoder.encode("TestPassword123!"));
        return userRepository.save(user);
    }

    private void grant(User user, String method, String url) {
        new TestPermissionAssigner(
                roleRepository,
                userRoleRepository,
                permissionRepository,
                rolePermissionRepository
        ).grant(user, method, url);
    }

    private String tokenFor(Long userId) {
        return tokenFor(userId.toString());
    }

    private String tokenFor(String subject) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("ms-security")
                .subject(subject)
                .issuedAt(now)
                .expiresAt(now.plusSeconds(300))
                .id(UUID.randomUUID().toString())
                .claim("email", "authorization-tests@example.com")
                .build();

        return jwtEncoder.encode(
                JwtEncoderParameters.from(
                        JwsHeader.with(MacAlgorithm.HS256).build(),
                        claims
                )
        ).getTokenValue();
    }
}
