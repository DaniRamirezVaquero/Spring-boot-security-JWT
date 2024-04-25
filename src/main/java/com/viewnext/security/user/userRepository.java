package com.viewnext.security.user;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface userRepository extends JpaRepository<User, Integer>{

  Optional<User> findByEmail(String email);
}
