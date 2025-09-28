package org.example.jwtauth.controller;

import org.example.jwtauth.dto.AuthRequest;
import org.example.jwtauth.dto.AuthResponse;
import org.example.jwtauth.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    @Autowired
    public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest request) {
        try {
            // UsernamePasswordAuthenticationToken is a wrapper used for beolw fields
            // Before authentication :
            //      principal = username
            //      credentials = password
            //      authorities = null
            //      authenticated = false
            // After authentication :
            //      principal = UserDetails (full user object)
            //      credentials = null (password cleared for safety)
            //      authorities = roles/permissions
            //      authenticated = true

            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            @SuppressWarnings("unchecked")
            List<String> roles = auth.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            String token = jwtUtil.generateToken(auth.getName(), roles);
            return ResponseEntity.ok(new AuthResponse(token, jwtUtilExpiration()));
        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(401).build();
        } catch (AuthenticationException ex) {
            return ResponseEntity.status(403).build();
        }
    }

    // Helper: read expiration value to return to client (optional)
    private long jwtUtilExpiration() {
        // this is a little coupling to the JwtUtil's configured expiry; you may expose via property or service
        try {
            java.lang.reflect.Field f = JwtUtil.class.getDeclaredField("jwtExpirationMs");
            f.setAccessible(true);
            return (long) f.get(jwtUtil);
        } catch (Exception e) {
            return 0L;
        }
    }
}
