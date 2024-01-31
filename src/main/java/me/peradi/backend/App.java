package me.peradi.backend;

import me.peradi.backend.models.Role;
import me.peradi.backend.models.User;
import me.peradi.backend.repositories.UserRepository;
import me.peradi.backend.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.UUID;

@SpringBootApplication
@EnableAsync
@EnableScheduling
public class App implements CommandLineRunner {

	@Autowired
	private UserService userService;

	@Autowired
	private UserRepository userRepository;

	@Value("${admin.username}")
	private String adminUsername;
	@Value("${admin.password}")
	private String adminPassword;
	@Value("${admin.email}")
	private String adminEmail;
	@Value("${admin.name}")
	private String adminName;

	public static void main(String[] args) {
		SpringApplication.run(App.class, args);
	}

	public void run(String... args) {
		User user = userService.getByUsername("${admin.username}");
		if (user == null) {
			UUID uuid = UUID.randomUUID();
			adminPassword = new BCryptPasswordEncoder().encode(adminPassword);
			user = new User(uuid, adminUsername, adminEmail, adminPassword, adminName, Role.ADMIN);

			userRepository.save(user);
		}
	}
}
