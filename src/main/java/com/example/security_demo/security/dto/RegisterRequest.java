package com.example.security_demo.security.dto;

import java.util.Set;

public record RegisterRequest(String userName, String email, String password) {
}
