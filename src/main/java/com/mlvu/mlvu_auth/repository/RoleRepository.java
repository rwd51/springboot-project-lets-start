package com.mlvu.mlvu_auth.repository;

import com.mlvu.mlvu_auth.entity.ERole;
import com.mlvu.mlvu_auth.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
    
    Boolean existsByName(ERole name);
}