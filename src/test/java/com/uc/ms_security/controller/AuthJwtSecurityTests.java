package com.uc.ms_security.controller;

import com.uc.ms_security.entity.User;
import com.uc.ms_security.TestPermissionAssigner;
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
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AuthJwtSecurityTests {

    private static final String EMAIL = "jwt-tests@example.com";
    private static final String PASSWORD = "LoginPassword123!";

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

    @Autowired
    private JwtEncoder jwtEncoder;

    @Test
    void loginReturnsBearerTokenWithFifteenMinuteExpiry() throws Exception {
        createUser();

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody(EMAIL, PASSWORD)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresAt").isNotEmpty())
                .andReturn();

        JsonNode response = objectMapper.readTree(
                result.getResponse().getContentAsString()
        );
        Instant expiration = Instant.parse(response.get("expiresAt").asText());
        assertThat(expiration).isAfter(Instant.now().plusSeconds(14 * 60));
        assertThat(expiration).isBefore(Instant.now().plusSeconds(16 * 60));
    }

    @Test
    void unknownEmailAndWrongPasswordReturnSameUnauthorizedError()
            throws Exception {
        createUser();

        MvcResult unknownEmail = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody("unknown@example.com", PASSWORD)))
                .andExpect(status().isUnauthorized())
                .andReturn();
        MvcResult wrongPassword = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody(EMAIL, "WrongPassword123!")))
                .andExpect(status().isUnauthorized())
                .andReturn();

        JsonNode unknownError = objectMapper.readTree(
                unknownEmail.getResponse().getContentAsString()
        );
        JsonNode passwordError = objectMapper.readTree(
                wrongPassword.getResponse().getContentAsString()
        );
        assertThat(unknownError.get("message").asText())
                .isEqualTo("Credenciales incorrectas");
        assertThat(passwordError.get("message").asText())
                .isEqualTo(unknownError.get("message").asText());
    }

    @Test
    void protectedEndpointRejectsMissingAndTamperedTokens() throws Exception {
        createUser();
        String token = loginAndGetToken();

        mockMvc.perform(get("/api/users"))
                .andExpect(status().isUnauthorized());

        String[] tokenParts = token.split("\\.");
        tokenParts[2] = (tokenParts[2].charAt(0) == 'A' ? "B" : "A")
                + tokenParts[2].substring(1);
        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer " + String.join(".", tokenParts)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void validTokenAllowsProtectedEndpointAndExpiredTokenIsRejected()
            throws Exception {
        User user = createUser();
        grantPermission(user, "GET", "/api/users");
        String validToken = loginAndGetToken();

        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer " + validToken))
                .andExpect(status().isOk())
                .andDo(result -> assertThat(
                        result.getRequest().getSession(false)
                ).isNull());

        String expiredToken = generateExpiredToken(user);
        mockMvc.perform(get("/api/users")
                        .header("Authorization", "Bearer " + expiredToken))
                .andExpect(status().isUnauthorized());
    }

    private User createUser() {
        User user = new User();
        user.setName("JWT Test User");
        user.setEmail(EMAIL);
        user.setPassword(passwordEncoder.encode(PASSWORD));
        return userRepository.save(user);
    }

    private void grantPermission(User user, String method, String url) {
        new TestPermissionAssigner(
                roleRepository,
                userRoleRepository,
                permissionRepository,
                rolePermissionRepository
        ).grant(user, method, url);
    }

    private String loginAndGetToken() throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginBody(EMAIL, PASSWORD)))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readTree(result.getResponse().getContentAsString())
                .get("accessToken")
                .asText();
    }

    private String generateExpiredToken(User user) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("ms-security")
                .subject(user.getId().toString())
                .issuedAt(now.minusSeconds(1200))
                .expiresAt(now.minusSeconds(60))
                .id(UUID.randomUUID().toString())
                .claim("email", user.getEmail())
                .build();

        return jwtEncoder.encode(
                JwtEncoderParameters.from(
                        JwsHeader.with(MacAlgorithm.HS256).build(),
                        claims
                )
        ).getTokenValue();
    }

    private String loginBody(String email, String password) {
        return """
                {
                  "email": "%s",
                  "password": "%s"
                }
                """.formatted(email, password);
    }
}
