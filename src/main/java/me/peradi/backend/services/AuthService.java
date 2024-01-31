package me.peradi.backend.services;

import me.peradi.backend.models.ForgetPasswordRequest;
import me.peradi.backend.models.Role;
import me.peradi.backend.models.User;
import me.peradi.backend.models.dto.JwtAuthenticationDTO;
import me.peradi.backend.repositories.AuthRepository;
import me.peradi.backend.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.MailException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.UUID;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final AuthRepository authRepository;
    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final EmailService emailService;

    public static HashSet<ForgetPasswordRequest> forgetPasswordRequests = new HashSet<>();

    @Autowired
    public AuthService(AuthenticationManager authenticationManager, AuthRepository authRepository, JwtService jwtService, UserRepository userRepository, EmailService emailService) {
        this.authenticationManager = authenticationManager;
        this.authRepository = authRepository;
        this.jwtService = jwtService;
        this.userRepository = userRepository;
        this.emailService = emailService;
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

    public boolean addForgetPasswordRequest(String username) {
        User user = userRepository.findByUsername(username);

        if(user == null)
            throw new UsernameNotFoundException("User not found.");

        StringBuilder verifyCode = new StringBuilder();

        for(int i = 0; i < 6; i++) {
            if (i % 2 == 0)
                verifyCode.append((int) (Math.random() * 10));
            else
                verifyCode.append((char) (Math.random() * 25 + 65));
        }

        try {
            emailService.sendEmail(user.getEmail(), "Forget Password", "Your verify code is: " + String.valueOf(verifyCode));
        } catch (MailException e) {
            return false;
        }

        ForgetPasswordRequest forgetPasswordRequest = new ForgetPasswordRequest(user.getUUID(), LocalDateTime.now(), verifyCode.toString());

        forgetPasswordRequests.removeIf(request -> request.getUuid().equals(user.getUUID()));
        forgetPasswordRequests.add(forgetPasswordRequest);

        return true;
    }

    public boolean forgetPassword(String uuid, String verifyCode, String newPassword) {
        User user = userRepository.findByUUID(uuid);

        if(user == null)
            throw new UsernameNotFoundException("User not found.");

        ForgetPasswordRequest forgetPasswordRequest =  forgetPasswordRequests.stream().filter(request -> request.getUuid().toString().equals(uuid)).findFirst().orElseThrow(() -> new RuntimeException("Forget password request not found."));

        if(!forgetPasswordRequest.getVerifyCode().equals(verifyCode))
            throw new RuntimeException("Invalid verify code.");

        user.setPassword(new BCryptPasswordEncoder().encode(newPassword));

        boolean status = userRepository.update(user);

        if(status)
            forgetPasswordRequests.remove(forgetPasswordRequest);

        return status;
    }
}
