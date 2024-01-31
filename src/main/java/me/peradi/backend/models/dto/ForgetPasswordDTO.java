package me.peradi.backend.models.dto;

public class ForgetPasswordDTO {

    private String username;

    public ForgetPasswordDTO(String username, String email) {
        this.username = username;
    }

    public String getUsername() {
        return this.username;
    }
}
