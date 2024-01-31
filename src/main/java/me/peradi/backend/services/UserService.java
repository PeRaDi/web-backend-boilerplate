package me.peradi.backend.services;

import me.peradi.backend.models.User;
import me.peradi.backend.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;

    @Autowired
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return userRepository.findByUsername(username);
    }

    public User getByUUID(String uuid) {
        User user = userRepository.findByUUID(uuid);

        if(user == null)
            throw new UsernameNotFoundException("User not found.");

        return user;
    }

    public User getByUsername(String username) {
        User user = userRepository.findByUsername(username);

        if(user == null)
            throw new UsernameNotFoundException("User not found.");

        return user;
    }

    public User getByEmail(String email) {
        User user = userRepository.findByEmail(email);

        if(user == null)
            throw new UsernameNotFoundException("User not found.");

        return user;
    }
}
