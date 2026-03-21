package com.n4d3sh1k4.security_service.domain.repository;

import com.n4d3sh1k4.security_service.domain.model.security.RefreshToken;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    @Modifying
    @Transactional
    void deleteByUser(User user);

    @Transactional
    void deleteByToken(String token);
}
