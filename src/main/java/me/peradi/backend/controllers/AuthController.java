package me.peradi.backend.controllers;

import jakarta.servlet.http.HttpServletResponse;
import me.peradi.backend.models.User;
import me.peradi.backend.models.dto.*;
import me.peradi.backend.models.responses.Response;
import me.peradi.backend.services.AuthService;
import me.peradi.backend.utils.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
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
    public ResponseEntity<Response> signup(@RequestBody SignupDTO signupDTO) {
        String username = signupDTO.getUsername();
        String email = signupDTO.getEmail();
        String name = signupDTO.getName();
        String password = signupDTO.getPassword();

        if(StringUtils.isNullOrBlank(username) || StringUtils.isNullOrBlank(email) || StringUtils.isNullOrBlank(name) || StringUtils.isNullOrBlank(password))
            return new ResponseEntity<>(new Response(400, "Username, email, name, and password must be specified.", null), null, HttpServletResponse.SC_BAD_REQUEST);

        return authService.signUp(username, email, name, password);
    }

    @PostMapping("/signin")
    public ResponseEntity<Response> signin(@RequestBody SigninDTO signinDTO) {
        String username = signinDTO.getUsername();
        String password = signinDTO.getPassword();

        if(StringUtils.isNullOrBlank(username) || StringUtils.isNullOrBlank(password))
            return new ResponseEntity<>(new Response(400, "Username and password must be specified.", null), null, HttpServletResponse.SC_BAD_REQUEST);

        return authService.signIn(username, password);
    }

    @PostMapping("/refreshToken")
    public ResponseEntity<Response> refreshToken(@RequestBody RefreshTokenDTO refreshTokenDTO) {
        String refreshToken = refreshTokenDTO.getRefreshToken();

        if(StringUtils.isNullOrBlank(refreshToken))
            return new ResponseEntity<>(new Response(400, "Refresh token must be specified.", null), null, HttpServletResponse.SC_BAD_REQUEST);

        return authService.refreshToken(refreshToken);
    }

    @PostMapping("/logout")
    public ResponseEntity<Response> logout() {
        User userDetails = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        String uuid = userDetails.getUUID().toString();

        return authService.logout(uuid);
    }


    @PostMapping("/changePassword")
    public ResponseEntity<Response> changePassword(@RequestBody ChangePasswordDTO changePasswordDTO) {
        String oldPassword = changePasswordDTO.getOldPassword();
        String newPassword = changePasswordDTO.getNewPassword();

        if(StringUtils.isNullOrBlank(oldPassword) || StringUtils.isNullOrBlank(newPassword))
            return new ResponseEntity<>(new Response(400, "Old password and new password must be specified.", null), null, HttpServletResponse.SC_BAD_REQUEST);

        if(oldPassword.equals(newPassword))
            return new ResponseEntity<>(new Response(400, "Old password and new password must be specified.", null), null, HttpServletResponse.SC_BAD_REQUEST);

        User userDetails = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        return authService.changePassword(userDetails.getUUID().toString(), changePasswordDTO.getOldPassword(), changePasswordDTO.getNewPassword());
    }

    @PostMapping("/forgotPassword")
    public ResponseEntity<Response> forgotPassword(@RequestBody ForgetPasswordDTO forgetPasswordDTO) {
        String username = forgetPasswordDTO.getUsername();

        if(StringUtils.isNullOrBlank(username))
            return new ResponseEntity<>(new Response(400, "Username must be specified.", null), null, HttpServletResponse.SC_BAD_REQUEST);

        return authService.addForgotPasswordRequest(username);
    }

    @PostMapping("/forgotPasswordWithVerifyCode")
    public ResponseEntity<Response> forgotPassword(@RequestBody ForgetPasswordWithVerifyCodeDTO forgetPasswordWithVerifyCodeDTO) {
        String verifyCode = forgetPasswordWithVerifyCodeDTO.getVerifyCode();
        String newPassword = forgetPasswordWithVerifyCodeDTO.getNewPassword();

        if(StringUtils.isNullOrBlank(verifyCode) || StringUtils.isNullOrBlank(newPassword))
            return new ResponseEntity<>(new Response(400, "Verify code and new password must be specified.", null), null, HttpServletResponse.SC_BAD_REQUEST);

        return authService.forgotPassword(verifyCode, newPassword);
    }
}
