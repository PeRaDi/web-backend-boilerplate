package me.peradi.backend.services;

import jakarta.servlet.http.HttpServletResponse;
import me.peradi.backend.models.ForgetPasswordRequest;
import me.peradi.backend.models.Role;
import me.peradi.backend.models.User;
import me.peradi.backend.models.dto.JwtAuthenticationDTO;
import me.peradi.backend.models.responses.Response;
import me.peradi.backend.repositories.AuthRepository;
import me.peradi.backend.repositories.UserRepository;
import me.peradi.backend.utils.Codes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.MailException;
import org.springframework.security.authentication.*;
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

    public ResponseEntity<Response> signUp(String username, String email, String name, String password) {
        try {
            if (userRepository.findByUsername(username) != null)
                return new ResponseEntity<>(new Response(400, "User already exists.", null), null, HttpServletResponse.SC_BAD_REQUEST);

            UUID uuid;

            do {
                uuid = UUID.randomUUID();
            } while (userRepository.findByUUID(uuid.toString()) != null);

            User user = new User(uuid, username, email, new BCryptPasswordEncoder().encode(password), name, Role.USER);
            user = userRepository.save(user);

            return new ResponseEntity<>(new Response(200, "User created successfully.", user), null, HttpServletResponse.SC_OK);
        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, "Internal server error. Please contact the system administrator. (" + e.getMessage() + ")", e.toString()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Response> signIn(String username, String password) {
        try {
            User user = userRepository.findByUsername(username);

            if (user == null)
                return new ResponseEntity<>(new Response(400, "User doesn't exist.", null), null, HttpServletResponse.SC_BAD_REQUEST);

            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));

            String token = jwtService.generateToken(user);
            String refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);

            if (!authRepository.updateRefreshToken(user.getUUID().toString(), refreshToken))
                throw new Exception("Error updating refresh token.");

            return new ResponseEntity<>(new Response(200, "Signed in.", new JwtAuthenticationDTO(token, refreshToken)), null, HttpServletResponse.SC_OK);
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(new Response(401, "Bad credentials.", null), null, HttpServletResponse.SC_UNAUTHORIZED);
        } catch(LockedException e) {
            return new ResponseEntity<>(new Response(423, "User account is locked.", null), null, 423);
        } catch(DisabledException e) {
            return new ResponseEntity<>(new Response(403, "User account is disabled.", null), null, HttpServletResponse.SC_FORBIDDEN);
        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, "Internal server error. Please contact the system administrator. (" + e.getMessage() + ")", e.toString()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Response> refreshToken(String refreshToken) {
        try {

            String username = jwtService.extractUsername(refreshToken);
            User user = userRepository.findByUsername(username);

            if(user == null || !jwtService.isTokenValid(refreshToken, user) || !authRepository.isRefreshTokenValid(user.getUUID().toString(), refreshToken))
                return new ResponseEntity<>(new Response(400, "Invalid refresh token.", null), null, HttpServletResponse.SC_BAD_REQUEST);

            String token = jwtService.generateToken(user);
            refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);

            if(!authRepository.updateRefreshToken(user.getUUID().toString(), refreshToken))
                throw new Exception("Error updating refresh token.");

            return new ResponseEntity<>(new Response(200, "Token refreshed.", new JwtAuthenticationDTO(token, refreshToken)), null, HttpServletResponse.SC_OK);
        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, "Internal server error. Please contact the system administrator. (" + e.getMessage() + ")", e.toString()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Response> logout(String uuid) {
        try {
            User user = userRepository.findByUsername(uuid);

            if (user == null)
                return new ResponseEntity<>(new Response(400, "User doesn't exist.", null), null, HttpServletResponse.SC_BAD_REQUEST);

            if (!authRepository.deleteRefreshToken(user.getUUID().toString()))
                throw new Exception("Error deleting refresh token.");

            return new ResponseEntity<>(new Response(200, "Logged out.", null), null, HttpServletResponse.SC_OK);
        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, "Internal server error. Please contact the system administrator. (" + e.getMessage() + ")", e.toString()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Response> changePassword(String uuid, String oldPassword, String newPassword) {
        try {
            User user = userRepository.findByUUID(uuid);

            if (user == null)
                return new ResponseEntity<>(new Response(400, "Specified token doesn't correspond to an user.", null), null, HttpServletResponse.SC_BAD_REQUEST);

            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user.getUsername(), oldPassword));

            user.setPassword(new BCryptPasswordEncoder().encode(newPassword));

            if (!userRepository.update(user))
                return new ResponseEntity<>(new Response(500, "Error updating password.", null), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

            return new ResponseEntity<>(new Response(200, "Password changed.", null), null, HttpServletResponse.SC_OK);
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(new Response(401, "Bad credentials.", null), null, HttpServletResponse.SC_UNAUTHORIZED);
        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, "Internal server error. Please contact the system administrator. (" + e.getMessage() + ")", e.toString()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Response> addForgotPasswordRequest(String username) {
        try {
            User user = userRepository.findByUsername(username);

            if (user == null)
                return new ResponseEntity<>(new Response(400, "User doesn't exist.", null), null, HttpServletResponse.SC_BAD_REQUEST);


            String verifyCode = Codes.generatePasswordResetCode();

            ForgetPasswordRequest forgetPasswordRequest = new ForgetPasswordRequest(user.getUUID(), LocalDateTime.now(), verifyCode);

            forgetPasswordRequests.removeIf(request -> request.getUuid().equals(user.getUUID()));
            forgetPasswordRequests.add(forgetPasswordRequest);

            emailService.sendEmail(user.getEmail(), "Forget Password", "Your verify code is: " + verifyCode);

            return new ResponseEntity<>(new Response(200, "Password reset email sent.", null), null, HttpServletResponse.SC_OK);
        } catch (MailException e) {
            return new ResponseEntity<>(new Response(500, "Error sending email.", null), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, "Internal server error. Please contact the system administrator. (" + e.getMessage() + ")", e.toString()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    public ResponseEntity<Response> forgotPassword(String verifyCode, String newPassword) {
        try {
            ForgetPasswordRequest forgetPasswordRequest = forgetPasswordRequests.stream().filter(request -> request.getVerifyCode().equals(verifyCode)).findFirst().orElse(null);

            if (forgetPasswordRequest == null)
                return new ResponseEntity<>(new Response(400, "Verify code is invalid.", null), null, HttpServletResponse.SC_BAD_REQUEST);

            User user = userRepository.findByUUID(forgetPasswordRequest.getUuid().toString());
            user.setPassword(new BCryptPasswordEncoder().encode(newPassword));

            boolean status = userRepository.update(user);

            if (!status)
                return new ResponseEntity<>(new Response(500, "Error updating password.", null), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

            forgetPasswordRequests.remove(forgetPasswordRequest);

            return new ResponseEntity<>(new Response(200, "Password changed.", null), null, HttpServletResponse.SC_OK);
        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, "Internal server error. Please contact the system administrator. (" + e.getMessage() + ")", e.toString()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
}
