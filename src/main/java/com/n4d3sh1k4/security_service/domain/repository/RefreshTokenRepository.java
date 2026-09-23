package com.n4d3sh1k4.security_service.domain.repository;

import com.n4d3sh1k4.security_service.domain.model.security.RefreshToken;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    List<RefreshToken> findAllByUserId(UUID userId);

    @Modifying
    @Transactional
    void deleteByUser(User user);

    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken r WHERE r.token = :token")
    void deleteByToken(@Param("token") String token);

    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken r WHERE r.user.id = :userId AND r.token <> :currentToken")
    void deleteByUserIdExceptToken(@Param("userId") UUID userId, @Param("currentToken") String currentToken);

    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken r WHERE r.user.id = :userId AND r.id = :sessionId AND r.token <> :currentToken")
    void deleteSessionById(@Param("userId") UUID userId, @Param("sessionId") UUID sessionId, @Param("currentToken") String currentToken);
}
