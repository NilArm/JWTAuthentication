// src/main/java/com/example/jwt/dto/AuthResponse.java
package org.example.jwtauth.dto;

public class AuthResponse {
    private String token;
    private long expiresInMs;

    public AuthResponse() {}
    public AuthResponse(String token, long expiresInMs) {
        this.token = token; this.expiresInMs = expiresInMs;
    }
    public String getToken() { return token; }
    public long getExpiresInMs() { return expiresInMs; }
}
