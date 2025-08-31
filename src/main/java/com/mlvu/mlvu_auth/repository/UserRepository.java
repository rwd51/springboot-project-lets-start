package com.mlvu.mlvu_auth.repository;

import com.mlvu.mlvu_auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    
    Optional<User> findByEmail(String email);
    
    Optional<User> findByClerkId(String clerkId);
    
    Optional<User> findByGithubId(String githubId);
    
    Boolean existsByUsername(String username);
    
    Boolean existsByEmail(String email);
}