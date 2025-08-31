package com.mlvu.mlvu_auth.security.oauth2;

import com.mlvu.mlvu_auth.entity.ERole;
import com.mlvu.mlvu_auth.entity.Role;
import com.mlvu.mlvu_auth.entity.User;
import com.mlvu.mlvu_auth.repository.RoleRepository;
import com.mlvu.mlvu_auth.repository.UserRepository;
import com.mlvu.mlvu_auth.security.oauth2.user.GithubOAuth2UserInfo;
import com.mlvu.mlvu_auth.security.oauth2.user.OAuth2UserInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        OAuth2UserInfo oAuth2UserInfo = new GithubOAuth2UserInfo(oAuth2User.getAttributes());
        
        if (!StringUtils.hasText(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail(oAuth2UserInfo.getEmail());
        User user;
        
        if (userOptional.isPresent()) {
            user = userOptional.get();
            user = updateExistingUser(user, oAuth2UserInfo);
        } else {
            user = registerNewUser(oAuth2UserRequest, oAuth2UserInfo);
        }

        return UserPrincipal.create(user, oAuth2User.getAttributes());
    }

    private User registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2UserInfo oAuth2UserInfo) {
        User user = new User();

        user.setGithubId(oAuth2UserInfo.getId());
        user.setUsername(oAuth2UserInfo.getName().toLowerCase().replace(" ", "") + "_" + oAuth2UserInfo.getId());
        user.setEmail(oAuth2UserInfo.getEmail());
        user.setFirstName(oAuth2UserInfo.getName().split(" ")[0]);
        if (oAuth2UserInfo.getName().split(" ").length > 1) {
            user.setLastName(oAuth2UserInfo.getName().split(" ")[1]);
        }
        user.setProfilePictureUrl(oAuth2UserInfo.getImageUrl());
        user.setEmailVerified(true);
        user.setEnabled(true);
        user.setAccountLocked(false);

        // Set default role as USER
        Set<Role> roles = new HashSet<>();
        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
        roles.add(userRole);
        user.setRoles(roles);

        return userRepository.save(user);
    }

    private User updateExistingUser(User existingUser, OAuth2UserInfo oAuth2UserInfo) {
        existingUser.setGithubId(oAuth2UserInfo.getId());
        existingUser.setFirstName(oAuth2UserInfo.getName().split(" ")[0]);
        if (oAuth2UserInfo.getName().split(" ").length > 1) {
            existingUser.setLastName(oAuth2UserInfo.getName().split(" ")[1]);
        }
        existingUser.setProfilePictureUrl(oAuth2UserInfo.getImageUrl());
        return userRepository.save(existingUser);
    }
}