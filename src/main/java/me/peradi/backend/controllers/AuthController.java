package me.peradi.backend.controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import me.peradi.backend.models.User;
import me.peradi.backend.models.dto.JwtAuthenticationDTO;
import me.peradi.backend.models.dto.RefreshTokenDTO;
import me.peradi.backend.models.dto.SigninDTO;
import me.peradi.backend.models.dto.SignupDTO;
import me.peradi.backend.models.responses.Response;
import me.peradi.backend.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signup")
    public Response signup(HttpServletRequest req, @RequestBody SignupDTO signupDTO) {
        User user;
        try {
            user = authService.signup(signupDTO.getUsername(), signupDTO.getEmail(), signupDTO.getName(), signupDTO.getPassword());
        } catch (Exception e) {
            return new Response(500, "Error creating user.", null, req.getRequestURI());
        }

        return new Response(200, "User created successfully.", user, req.getRequestURI());
    }

    @PostMapping("/signin")
    public ResponseEntity<Response> signin(HttpServletRequest req, @RequestBody SigninDTO signinDTO) {
        JwtAuthenticationDTO jwtAuthenticationDTO;

        try {
            jwtAuthenticationDTO = authService.signin(signinDTO.getUsername(), signinDTO.getPassword());
        } catch (UsernameNotFoundException e) {
            return new ResponseEntity<>(new Response(404, e.getMessage(), e.toString(), req.getRequestURI()), null, HttpServletResponse.SC_NOT_FOUND);
        } catch(BadCredentialsException e) {
            return new ResponseEntity<>(new Response(401, e.getMessage(), e.toString(), req.getRequestURI()), null, HttpServletResponse.SC_UNAUTHORIZED);
        } catch(LockedException e) {
            return new ResponseEntity<>(new Response(423, e.getMessage(), e.toString(), req.getRequestURI()), null, 423);
        } catch(DisabledException e) {
            return new ResponseEntity<>(new Response(403, e.getMessage(), e.toString(), req.getRequestURI()), null, HttpServletResponse.SC_FORBIDDEN);
        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, e.getMessage(), e.toString(), req.getRequestURI()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(new Response(200, "Signed in.", jwtAuthenticationDTO, req.getRequestURI()), null, HttpServletResponse.SC_OK);
    }

    @PostMapping("/refreshToken")
    public ResponseEntity<Response> refreshToken(HttpServletRequest req, @RequestBody RefreshTokenDTO refreshTokenDTO) {
        JwtAuthenticationDTO jwtAuthenticationDTO;

        try {
            jwtAuthenticationDTO = authService.refreshToken(refreshTokenDTO.getRefreshToken());
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(new Response(401, e.getMessage(), e.toString(), req.getRequestURI()), null, HttpServletResponse.SC_UNAUTHORIZED);
        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, e.getMessage(), e.toString(), req.getRequestURI()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(new Response(200, "Token refreshed.", jwtAuthenticationDTO, req.getRequestURI()), null, HttpServletResponse.SC_OK);
    }
}