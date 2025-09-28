package org.example.jwtauth.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Component
public class JwtUtil {

    private final Key signingKey;
    private final long jwtExpirationMs;

    public JwtUtil(
        @Value("${jwt.secret}") String base64Secret,
        @Value("${jwt.expiration-ms:3600000}") long jwtExpirationMs
    ) {
        byte[] keyBytes = Decoders.BASE64.decode(base64Secret);
        this.signingKey = Keys.hmacShaKeyFor(keyBytes); // validates key length
        this.jwtExpirationMs = jwtExpirationMs;
    }

    /**
     * Generate a signed JWT including roles (if provided).
     * @param subject usually username or user id
     * @param roles list of roles/authorities (optional)
     */
    public String generateToken(String subject, List<String> roles) {
        Instant now = Instant.now();
        JwtBuilder builder = Jwts.builder()
                .setSubject(subject)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plus(jwtExpirationMs, ChronoUnit.MILLIS)))
                .signWith(signingKey, SignatureAlgorithm.HS256);

        if (roles != null && !roles.isEmpty()) {
            builder.claim("roles", roles);
        }

        return builder.compact();
    }

    public String generateToken(String subject) {
        return generateToken(subject, Collections.emptyList());
    }

    private Claims parseClaims(String token) {
        // will throw subclasses of JwtException on failure; caller can handle appropriately
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public Optional<String> extractUsername(String token) {
        try {
            return Optional.ofNullable(parseClaims(token).getSubject());
        } catch (JwtException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    public Optional<List<String>> extractRoles(String token) {
        try {
            Claims claims = parseClaims(token);
            Object raw = claims.get("roles");
            if (raw instanceof List<?>) {
                List<?> rawList = (List<?>) raw;
                List<String> roles = new ArrayList<>(rawList.size());
                for (Object o : rawList) {
                    roles.add(String.valueOf(o));
                }
                return Optional.of(roles);
            }
            return Optional.empty();
        } catch (JwtException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            Date exp = parseClaims(token).getExpiration();
            return exp.before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            // treat other parsing errors as invalid/expired for safety
            return true;
        }
    }

    /**
     * Validates signature & expiry and that the subject matches the expected username.
     */
    public boolean validateToken(String token, String expectedUsername) {
        try {
            Claims claims = parseClaims(token);
            String subject = claims.getSubject();
            if (subject == null || !subject.equals(expectedUsername)) return false;
            Date expiration = claims.getExpiration();
            return expiration != null && expiration.after(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
