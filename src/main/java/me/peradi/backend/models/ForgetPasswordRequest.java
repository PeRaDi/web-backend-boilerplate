package me.peradi.backend.models;

import java.time.LocalDateTime;
import java.util.UUID;

public class ForgetPasswordRequest {

    private UUID uuid;
    private LocalDateTime createdAt;
    private String verifyCode;

    public ForgetPasswordRequest(UUID uuid, LocalDateTime createdAt, String code) {
        this.uuid = uuid;
        this.createdAt = createdAt;
        this.verifyCode = code;
    }

    public UUID getUuid() {
        return this.uuid;
    }

    public LocalDateTime getCreatedAt() {
        return this.createdAt;
    }

    public String getVerifyCode() {
        return this.verifyCode;
    }
}
