package me.peradi.backend.repositories;

import me.peradi.backend.models.Role;
import me.peradi.backend.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.UUID;

@Repository
public class UserRepository {

    private final JdbcTemplate jdbcTemplate;

    @Autowired
    public UserRepository(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public User findByUsername(String username) {
        String sql = "SELECT * FROM users WHERE username = ?";
        PreparedStatementSetter ps = preparedStatement -> preparedStatement.setString(1, username);
        List<User> users =  jdbcTemplate.query(sql, ps, new UserRowMapper());

        return (users.isEmpty()) ? null : users.get(0);
    }

    public User findByEmail(String email) {
        String sql = "SELECT * FROM users WHERE email = ?";
        PreparedStatementSetter ps = preparedStatement -> preparedStatement.setString(1, email);
        List<User> users = jdbcTemplate.query(sql, ps, new UserRowMapper());

        return (users.isEmpty()) ? null : users.get(0);
    }

    public User findByUUID(String uuid) {
        String sql = "SELECT * FROM users WHERE id = ?";
        PreparedStatementSetter ps = preparedStatement -> preparedStatement.setString(1, uuid);
        List<User> users = jdbcTemplate.query(sql, ps, new UserRowMapper());

        return (users.isEmpty()) ? null : users.get(0);
    }

    public User save(User user) {
        String sql = "INSERT INTO users (id, username, email, password, name, role) VALUES (?, ?, ?, ?, ?, ?)";
        int rows = jdbcTemplate.update(sql, user.getUUID().toString(), user.getUsername(), user.getEmail(), user.getPassword(), user.getName(), user.getRole().toString());

        return (rows > 0) ? user : null;
    }

    public boolean update(User user) {
        String sql = "UPDATE `users` SET `username` = ?, `email` = ?, `password` = ?, `name` = ?, `role` = ? WHERE `id` = ?";
        int rows = jdbcTemplate.update(sql, user.getUsername(), user.getEmail(), user.getPassword(), user.getName(), user.getRole().toString(), user.getUUID().toString());

        return rows > 0;
    }
}

class UserRowMapper implements RowMapper<User> {

    @Override
    public User mapRow(ResultSet rs, int rowNum) throws SQLException {
        UUID uuid = UUID.fromString(rs.getString("id"));
        String username = rs.getString("username");
        String email = rs.getString("email");
        String password = rs.getString("password");
        String name = rs.getString("name");
        Role role = Role.valueOf(rs.getString("role"));

        return new User(uuid, username, email, password, name, role);
    }
}
