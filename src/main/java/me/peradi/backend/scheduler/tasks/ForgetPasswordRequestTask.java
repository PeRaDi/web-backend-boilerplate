package me.peradi.backend.scheduler.tasks;

import me.peradi.backend.services.AuthService;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class ForgetPasswordRequestTask {

    @Async
    @Scheduled(fixedRate = 1000 * 60) // 1 minute
    public void forgetPasswordRequestTask() {
        AuthService.forgetPasswordRequests.removeIf(forgetPasswordRequest -> forgetPasswordRequest.getCreatedAt().plusMinutes(5).isBefore(LocalDateTime.now()));
    }
}
