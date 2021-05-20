package com.bms.user.repository;
import org.springframework.data.jpa.repository.JpaRepository;

import com.bms.user.model.UserDao;
public interface UserRepository extends JpaRepository<UserDao, Integer> {
    UserDao findByUsername(String username);
}