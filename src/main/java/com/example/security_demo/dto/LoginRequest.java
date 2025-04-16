package com.example.security_demo.dto;

public record LoginRequest(String userName, String password, boolean rememberMe) {
}
