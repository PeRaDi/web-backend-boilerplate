package me.peradi.backend.controllers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import me.peradi.backend.models.ForgetPasswordRequest;
import me.peradi.backend.models.User;
import me.peradi.backend.models.dto.*;
import me.peradi.backend.models.responses.Response;
import me.peradi.backend.services.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @Autowired
    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/signup")
    public ResponseEntity<Response> signup(HttpServletRequest req, @RequestBody SignupDTO signupDTO) {
        User user;
        try {
            user = authService.signup(signupDTO.getUsername(), signupDTO.getEmail(), signupDTO.getName(), signupDTO.getPassword());

            if(user == null)
                return new ResponseEntity<>(new Response(400, "User already exists.", null, req.getRequestURI()), null, HttpServletResponse.SC_BAD_REQUEST);

        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, "Error creating user.", null, req.getRequestURI()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(new Response(200, "User created successfully.", user, req.getRequestURI()), null, HttpServletResponse.SC_OK);
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

    @PostMapping("/logout")
    public ResponseEntity<Response> logout(HttpServletRequest req) {
        try {
            User userDetails = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

            boolean status = authService.logout(userDetails.getUUID());

            if(!status)
                return new ResponseEntity<>(new Response(500, "Error logging out.", null, req.getRequestURI()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(new Response(401, e.getMessage(), e.toString(), req.getRequestURI()), null, HttpServletResponse.SC_UNAUTHORIZED);
        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, e.getMessage(), e.toString(), req.getRequestURI()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(new Response(200, "Logged out.", null, req.getRequestURI()), null, HttpServletResponse.SC_OK);
    }

    @PostMapping("/changePassword")
    public ResponseEntity<Response> changePassword(HttpServletRequest req, @RequestBody ChangePasswordDTO changePasswordDTO) {
        try {
            if(changePasswordDTO.getNewPassword().equals(changePasswordDTO.getOldPassword()))
                return new ResponseEntity<>(new Response(400, "New password cannot be the same as old password.", null, req.getRequestURI()), null, HttpServletResponse.SC_BAD_REQUEST);

            User userDetails = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

            boolean status = authService.changePassword(userDetails.getUUID().toString(), changePasswordDTO.getOldPassword(), changePasswordDTO.getNewPassword());

            if(!status)
                return new ResponseEntity<>(new Response(500, "Error changing password.", null, req.getRequestURI()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

        } catch (BadCredentialsException e) {
            return new ResponseEntity<>(new Response(401, e.getMessage(), e.toString(), req.getRequestURI()), null, HttpServletResponse.SC_UNAUTHORIZED);
        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, e.getMessage(), e.toString(), req.getRequestURI()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(new Response(200, "Password changed.", null, req.getRequestURI()), null, HttpServletResponse.SC_OK);
    }

    @PostMapping("/forgetPassword")
    public ResponseEntity<Response> forgetPassword(HttpServletRequest req, @RequestBody ForgetPasswordDTO forgetPasswordDTO) {
        try {
            boolean status = authService.addForgetPasswordRequest(forgetPasswordDTO.getUsername());

            if(!status)
                return new ResponseEntity<>(new Response(500, "Error adding forget password request.", null, req.getRequestURI()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, e.getMessage(), e.toString(), req.getRequestURI()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(new Response(200, "Password reset email sent.", null, req.getRequestURI()), null, HttpServletResponse.SC_OK);
    }

    @PostMapping("/forgetPasswordWithVerifyCode")
    public ResponseEntity<Response> forgetPassword(HttpServletRequest req, @RequestBody ForgetPasswordWithVerifyCodeDTO forgetPasswordWithVerifyCodeDTO) {
        try {
            User userDetails = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

            boolean status = authService.forgetPassword(userDetails.getUUID().toString(), forgetPasswordWithVerifyCodeDTO.getVerifyCode(), forgetPasswordWithVerifyCodeDTO.getNewPassword());

            if (!status)
                return new ResponseEntity<>(new Response(500, "Error changing password.", null, req.getRequestURI()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);

        } catch (RuntimeException e) {
            return new ResponseEntity<>(new Response(400, e.getMessage(), e.toString(), req.getRequestURI()), null, HttpServletResponse.SC_BAD_REQUEST);
        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, e.getMessage(), e.toString(), req.getRequestURI()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(new Response(200, "Password changed.", null, req.getRequestURI()), null, HttpServletResponse.SC_OK);
    }
}
