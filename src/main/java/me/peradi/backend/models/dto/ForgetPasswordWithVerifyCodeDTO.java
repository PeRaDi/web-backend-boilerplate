package me.peradi.backend.models.dto;

public class ForgetPasswordWithVerifyCodeDTO {

    private String verifyCode;
    private String newPassword;

    public ForgetPasswordWithVerifyCodeDTO(String verifyCode, String newPassword) {
        this.verifyCode = verifyCode;
        this.newPassword = newPassword;
    }

    public String getVerifyCode() {
        return this.verifyCode;
    }

    public String getNewPassword() {
        return this.newPassword;
    }
}
