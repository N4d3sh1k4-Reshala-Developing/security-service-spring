package com.n4d3sh1k4.security_service.domain.repository;

import com.n4d3sh1k4.security_service.domain.model.security.Token;
import com.n4d3sh1k4.security_service.domain.model.security.TokenType;
import com.n4d3sh1k4.security_service.domain.model.users.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface TokenRepository extends JpaRepository<Token, UUID> {

    Optional<Token> findByToken(String token);

    Optional<Token> findByUserAndType(User user, TokenType type);

    void deleteByUserAndType(User user, TokenType type);
}
