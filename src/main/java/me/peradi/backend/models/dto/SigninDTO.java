package me.peradi.backend.models.dto;

public class SigninDTO {

    private String username;
    private String password;

    public SigninDTO(String emailOrUsername, String password) {
        this.username = emailOrUsername;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
