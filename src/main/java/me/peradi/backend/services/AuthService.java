package me.peradi.backend.services;
import me.peradi.backend.models.Role;
import me.peradi.backend.models.User;
import me.peradi.backend.models.dto.JwtAuthenticationDTO;
import me.peradi.backend.repositories.AuthRepository;
import me.peradi.backend.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.UUID;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final AuthRepository authRepository;
    private final JwtService jwtService;
    private final UserRepository userRepository;

    @Autowired
    public AuthService(AuthenticationManager authenticationManager, AuthRepository authRepository, JwtService jwtService, UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.authRepository = authRepository;
        this.jwtService = jwtService;
        this.userRepository = userRepository;
    }

    public User signup(String username, String email, String name, String password) {
        if(userRepository.findByUsername(username) != null)
            return null;

        UUID uuid;

        do {
            uuid = UUID.randomUUID();
        } while (userRepository.findByUUID(uuid.toString()) != null);

        User user = new User(uuid, username, email, new BCryptPasswordEncoder().encode(password), name, Role.USER);

        return userRepository.save(user);
    }

    public JwtAuthenticationDTO signin(String username, String password) {
        User user = userRepository.findByUsername(username);

        if(user == null)
            throw new UsernameNotFoundException("User not found.");

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

        String token = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);

        if(!authRepository.updateRefreshToken(user.getUUID().toString(), refreshToken))
            throw new RuntimeException("Error updating refresh token.");

        return new JwtAuthenticationDTO(token, refreshToken);
    }

    public JwtAuthenticationDTO refreshToken(String refreshToken) {
        String username = jwtService.extractUsername(refreshToken);
        User user = userRepository.findByUsername(username);

        if(user == null || !jwtService.isTokenValid(refreshToken, user) || !authRepository.isRefreshTokenValid(user.getUUID().toString(), refreshToken))
            throw new BadCredentialsException("Invalid refresh token.");

        String token = jwtService.generateToken(user);
        refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);

        if(!authRepository.updateRefreshToken(user.getUUID().toString(), refreshToken))
            throw new RuntimeException("Error updating refresh token.");

        return new JwtAuthenticationDTO(token, refreshToken);
    }

    public boolean logout(UUID uuid) {
        User user = userRepository.findByUsername(uuid.toString());

        if(user == null)
            throw new UsernameNotFoundException("User not found.");

        return authRepository.deleteRefreshToken(user.getUUID().toString());
    }

    public boolean changePassword(String uuid, String oldPassword, String newPassword) {
        User user = userRepository.findByUUID(uuid);

        if(user == null)
            throw new UsernameNotFoundException("User not found.");

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), oldPassword));

        user.setPassword(new BCryptPasswordEncoder().encode(newPassword));

        return userRepository.update(user);
    }
}
