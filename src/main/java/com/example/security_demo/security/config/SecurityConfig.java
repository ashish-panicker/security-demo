package com.example.security_demo.security.config;

import com.example.security_demo.security.filters.JwtFilter;
import jakarta.servlet.Filter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private Logger logger = LoggerFactory.getLogger(getClass().getName());
    private final UserDetailsService userDetailsService;
    private final JwtFilter jwtAuthFilter;

    public SecurityConfig(UserDetailsService userDetailsService, JwtFilter jwtAuthFilter) {
        this.userDetailsService = userDetailsService;
        this.jwtAuthFilter = jwtAuthFilter;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    InMemoryUserDetailsManager inMemoryUserDetailsManager() {
//        UserDetails user, admin;
//        user = User.withUsername("ashish").roles("USER")
//                .password(passwordEncoder().encode("Welcome123"))
//                .build();
//        logger.info("User: {} {}", user, user.getPassword());
//        admin = User.withUsername("admin").roles("ADMIN")
//                .password(passwordEncoder().encode("Welcome123"))
//                .build();
//        logger.info("Admin: {} {}", admin, admin.getPassword());
//        return new InMemoryUserDetailsManager(user, admin);
//    }

    @Bean
    AuthenticationManager authenticationManager(HttpSecurity httpSecurity) throws Exception {
        return httpSecurity
                .getSharedObject(AuthenticationManagerBuilder.class)
                .authenticationProvider(authenticationProvider())
                .build();
    }

    @Bean
    DaoAuthenticationProvider authenticationProvider() {
        var authProvider = new DaoAuthenticationProvider();
        authProvider.setPasswordEncoder(passwordEncoder());
        authProvider.setUserDetailsService(userDetailsService);
        return authProvider;
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/h2", "/h2/**", "/public", "/auth/**", "/").permitAll()
                        .requestMatchers("/users", "/users/**").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/admin", "/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
                .headers(headers -> headers.frameOptions(
                        frameOptions -> frameOptions.disable()))
                .httpBasic(Customizer.withDefaults());
        return httpSecurity.build();
    }
}
