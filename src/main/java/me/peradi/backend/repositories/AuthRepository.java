package me.peradi.backend.repositories;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.Objects;

@Repository
public class AuthRepository {

    private final JdbcTemplate jdbcTemplate;

    public AuthRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public boolean updateRefreshToken(String userUUID, String refreshToken) {
        String sql = "UPDATE users SET `refresh_token` = ? WHERE `id` = ?";
        int rows = jdbcTemplate.update(sql, refreshToken, userUUID);

        return rows > 0;
    }

    public boolean isRefreshTokenValid(String userUUID, String refreshToken) {
        String sql = "SELECT `refresh_token` FROM users WHERE `id` = ?";

        return Objects.equals(jdbcTemplate.queryForObject(sql, String.class, userUUID), refreshToken);
    }

    public boolean deleteRefreshToken(String userUUID) {
        String sql = "UPDATE users SET `refresh_token` = NULL WHERE `id` = ?";
        int rows = jdbcTemplate.update(sql, userUUID);

        return rows > 0;
    }
}
