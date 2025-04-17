package com.example.security_demo.security.controller;

import com.example.security_demo.security.dto.RegisterRequest;
import com.example.security_demo.security.dto.LoginRequest;
import com.example.security_demo.security.model.AppUser;
import com.example.security_demo.security.repo.AppUserRepository;
import com.example.security_demo.security.util.JwtUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private Logger logger = LoggerFactory.getLogger(getClass().getName());
    private final AuthenticationManager authenticationManager;
    private final AppUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public AuthController(AuthenticationManager authenticationManager, AppUserRepository userRepository,
                          PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterRequest request) {
        if (userRepository.findByUserName(request.userName()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("User already exists");
        }
        var user = new AppUser(request.userName(),
                passwordEncoder.encode(request.password()),
                request.email(), Set.of("USER"));
        userRepository.save(user);
        return ResponseEntity.status(HttpStatus.CREATED).body("User created");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        if (userRepository.findByUserName(request.userName()).isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User does not exists");
        }
        var unAuthenticatedUser = new UsernamePasswordAuthenticationToken(
                request.userName(), request.password()
        );
        // Authenticate the user
        Authentication authenticatedUser =
                authenticationManager.authenticate(unAuthenticatedUser);
        String token = jwtUtil.generateToken((UserDetails) authenticatedUser.getPrincipal());
        return ResponseEntity.ok(Map.of("status", HttpStatus.OK, "token", token));

    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<String> handleAuthException(AuthenticationException ae) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ae.getMessage());
    }
}
