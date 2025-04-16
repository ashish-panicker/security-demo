package com.example.security_demo.controller;

import com.example.security_demo.dto.LoginRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private Logger logger = LoggerFactory.getLogger(getClass().getName());

    private final UserDetailsService userDetailsService;
    private final RememberMeServices rememberMeServices;
    private final HttpSession session;

    public AuthController(UserDetailsService userDetailsService, RememberMeServices rememberMeServices, HttpSession session) {
        this.userDetailsService = userDetailsService;
        this.rememberMeServices = rememberMeServices;
        this.session = session;
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequest loginRequest,
                                        HttpServletRequest request,
                                        HttpServletResponse response) {
        UserDetails userDetails = userDetailsService.loadUserByUsername(loginRequest.userName());
        if (!new BCryptPasswordEncoder().matches(loginRequest.password(), userDetails.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
        Authentication auth = new UsernamePasswordAuthenticationToken(userDetails, null,
                userDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(auth);
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY,
                SecurityContextHolder.getContext());
        logger.info("loginRequest.rememberMe() {}", loginRequest.rememberMe());
        logger.info("auth {}", auth);
        if (loginRequest.rememberMe()) {
            rememberMeServices.loginSuccess(request, response, auth);
        }
        return ResponseEntity.ok("Logged in as " +
                SecurityContextHolder.getContext().getAuthentication().getName());
    }

    @GetMapping("/logout")
    public ResponseEntity<String> logout(
            HttpServletRequest request,
            HttpServletResponse response) {
        request.getSession().invalidate();
        return ResponseEntity.ok("Logged out" );
    }

}
