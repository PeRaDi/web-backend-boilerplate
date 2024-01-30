package me.peradi.backend.controllers;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import me.peradi.backend.models.User;
import me.peradi.backend.models.responses.Response;
import me.peradi.backend.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/users")
public class UsersController {

    private final UserService userService;

    @Autowired
    public UsersController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/getByUUID/{uuid}")
    public ResponseEntity<Response> getUser(HttpServletRequest req, @PathVariable("uuid") String uuid) {
        User user;
        try {
            user = userService.getByUUID(uuid);
        } catch (UsernameNotFoundException e) {
            return new ResponseEntity<>(new Response(404, e.getMessage(), e.toString(), req.getRequestURI()), null, HttpServletResponse.SC_NOT_FOUND);
        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, "Error getting user.", null, req.getRequestURI()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(new Response(200, "User retrieved successfully.", user, req.getRequestURI()), null, HttpServletResponse.SC_OK);
    }

    @GetMapping("/getByUsername/{username}")
    public ResponseEntity<Response> getUserByUsername(HttpServletRequest req, @PathVariable("username") String username) {
        User user;
        try {
            user = userService.getByUsername(username);
        } catch (UsernameNotFoundException e) {
            return new ResponseEntity<>(new Response(404, e.getMessage(), e.toString(), req.getRequestURI()), null, HttpServletResponse.SC_NOT_FOUND);
        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, "Error getting user.", null, req.getRequestURI()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(new Response(200, "User retrieved successfully.", user, req.getRequestURI()), null, HttpServletResponse.SC_OK);
    }

    @GetMapping("/getByEmail/{email}")
    public ResponseEntity<Response> getUserByEmail(HttpServletRequest req, @PathVariable("email") String email) {
        User user;
        try {
            user = userService.getByEmail(email);
        } catch (UsernameNotFoundException e) {
            return new ResponseEntity<>(new Response(404, e.getMessage(), e.toString(), req.getRequestURI()), null, HttpServletResponse.SC_NOT_FOUND);
        } catch (Exception e) {
            return new ResponseEntity<>(new Response(500, "Error getting user.", null, req.getRequestURI()), null, HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(new Response(200, "User retrieved successfully.", user, req.getRequestURI()), null, HttpServletResponse.SC_OK);
    }

}
