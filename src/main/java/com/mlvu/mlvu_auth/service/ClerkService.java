package com.mlvu.mlvu_auth.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.mlvu.mlvu_auth.entity.ERole;
import com.mlvu.mlvu_auth.entity.RefreshToken;
import com.mlvu.mlvu_auth.entity.Role;
import com.mlvu.mlvu_auth.entity.User;
import com.mlvu.mlvu_auth.payload.request.ClerkWebhookRequest;
import com.mlvu.mlvu_auth.payload.response.JwtResponse;
import com.mlvu.mlvu_auth.repository.RoleRepository;
import com.mlvu.mlvu_auth.repository.UserRepository;
import com.mlvu.mlvu_auth.security.jwt.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class ClerkService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private JwtUtil jwtUtil;
    
    @Autowired
    private RefreshTokenService refreshTokenService;

    @Value("${clerk.api.key}")
    private String clerkApiKey;

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();

    public ResponseEntity<?> validateClerkToken(String clerkToken) {
        try {
            // Validate Clerk token by making request to Clerk API
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + clerkApiKey);
            
            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                    "https://api.clerk.com/v1/sessions/" + clerkToken,
                    HttpMethod.GET,
                    entity,
                    String.class
            );
            
            if (response.getStatusCode().is2xxSuccessful()) {
                JsonNode jsonResponse = objectMapper.readTree(response.getBody());
                String clerkUserId = jsonResponse.path("data").path("user_id").asText();
                
                // Get user details from Clerk
                ResponseEntity<String> userResponse = restTemplate.exchange(
                        "https://api.clerk.com/v1/users/" + clerkUserId,
                        HttpMethod.GET,
                        entity,
                        String.class
                );
                
                if (userResponse.getStatusCode().is2xxSuccessful()) {
                    JsonNode userJson = objectMapper.readTree(userResponse.getBody());
                    
                    String email = userJson.path("email_addresses").path(0).path("email_address").asText();
                    String firstName = userJson.path("first_name").asText();
                    String lastName = userJson.path("last_name").asText();
                    
                    // Check if user exists in our database
                    User user = userRepository.findByClerkId(clerkUserId).orElse(null);
                    
                    if (user == null) {
                        // Create new user
                        user = User.builder()
                                .clerkId(clerkUserId)
                                .email(email)
                                .username(email.split("@")[0] + "_" + clerkUserId.substring(0, 8))
                                .firstName(firstName)
                                .lastName(lastName)
                                .isEmailVerified(true)
                                .isEnabled(true)
                                .isAccountLocked(false)
                                .build();
                                
                        // Set default role as USER
                        Set<Role> roles = new HashSet<>();
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                        user.setRoles(roles);
                    }
                    
                    // Update last login
                    user.setLastLoginAt(LocalDateTime.now());
                    userRepository.save(user);
                    
                    // Create JWT token
                    List<GrantedAuthority> authorities = user.getRoles().stream()
                            .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                            .collect(Collectors.toList());
                    
                    Authentication authentication = new UsernamePasswordAuthenticationToken(
                            user.getUsername(), null, authorities);
                    
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    String jwt = jwtUtil.generateTokenFromUsername(user.getUsername());
                    
                    // Create refresh token
                    RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getId());
                    
                    List<String> roles = user.getRoles().stream()
                            .map(role -> role.getName().name())
                            .collect(Collectors.toList());
                    
                    return ResponseEntity.ok(new JwtResponse(
                            jwt,
                            refreshToken.getToken(),
                            user.getId(),
                            user.getUsername(),
                            user.getEmail(),
                            roles
                    ));
                }
            }
            
            return ResponseEntity.badRequest().body("Invalid Clerk token");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error processing Clerk token: " + e.getMessage());
        }
    }

    public ResponseEntity<?> handleWebhook(ClerkWebhookRequest webhookRequest) {
        try {
            String eventType = webhookRequest.getType();
            
            switch (eventType) {
                case "user.created":
                    return handleUserCreated(webhookRequest.getData());
                case "user.updated":
                    return handleUserUpdated(webhookRequest.getData());
                case "user.deleted":
                    return handleUserDeleted(webhookRequest.getData());
                default:
                    return ResponseEntity.ok("Event type not handled: " + eventType);
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error processing webhook: " + e.getMessage());
        }
    }

    private ResponseEntity<?> handleUserCreated(JsonNode data) {
        try {
            String clerkId = data.path("id").asText();
            String email = data.path("email_addresses").path(0).path("email_address").asText();
            String firstName = data.path("first_name").asText();
            String lastName = data.path("last_name").asText();
            
            // Create new user in our database
            User user = User.builder()
                    .clerkId(clerkId)
                    .email(email)
                    .username(email.split("@")[0] + "_" + clerkId.substring(0, 8))
                    .firstName(firstName)
                    .lastName(lastName)
                    .isEmailVerified(true)
                    .isEnabled(true)
                    .isAccountLocked(false)
                    .build();
                    
            // Set default role as USER
            Set<Role> roles = new HashSet<>();
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
            user.setRoles(roles);
            
            userRepository.save(user);
            
            return ResponseEntity.ok("User created successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error creating user: " + e.getMessage());
        }
    }

    private ResponseEntity<?> handleUserUpdated(JsonNode data) {
        try {
            String clerkId = data.path("id").asText();
            User user = userRepository.findByClerkId(clerkId)
                    .orElseThrow(() -> new RuntimeException("User not found with Clerk ID: " + clerkId));
            
            String email = data.path("email_addresses").path(0).path("email_address").asText();
            String firstName = data.path("first_name").asText();
            String lastName = data.path("last_name").asText();
            
            // Update user details
            user.setEmail(email);
            user.setFirstName(firstName);
            user.setLastName(lastName);
            
            userRepository.save(user);
            
            return ResponseEntity.ok("User updated successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error updating user: " + e.getMessage());
        }
    }

    private ResponseEntity<?> handleUserDeleted(JsonNode data) {
        try {
            String clerkId = data.path("id").asText();
            User user = userRepository.findByClerkId(clerkId)
                    .orElseThrow(() -> new RuntimeException("User not found with Clerk ID: " + clerkId));
            
            // Delete user
            userRepository.delete(user);
            
            return ResponseEntity.ok("User deleted successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error deleting user: " + e.getMessage());
        }
    }
}