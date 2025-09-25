# JWTAuthentication

Authentication is the process of verifying the identity of a user, device, or system to ensure that access is granted only to authorized entities. This critical security step protects sensitive information, systems, and resources from unauthorized use or access.

API Authentication includes secures data exchange between software applications using methods like API keys, OAuth tokens, or JSON Web Tokens (JWTs).

JWT cotains : Base64(Header) + "." + Base64(Payload) + "." + Signature

Example :
JWT = eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqb2huX2RvZSIsInJvbGVzIjpbIlJPTEVfVVNFUiJdLCJleHAiOjE2OTU5MDM2MDB9.R-3rT5YcJ9yTrCdfcP8uT3R-ABtU7Mv6dRkDp8q3Djs
1st part = eyJhbGciOiJIUzI1NiJ9
    Base64URL decoded = { "alg": "HS256" }
2nd part = eyJzdWIiOiJqb2huX2RvZSIsInJvbGVzIjpbIlJPTEVfVVNFUiJdLCJleHAiOjE2OTU5MDM2MDB9
    Base64URL decoded = {"sub": "john_doe","roles": ["ROLE_USER"],"exp": 1695903600}
3rd part = R-3rT5YcJ9yTrCdfcP8uT3R-ABtU7Mv6dRkDp8q3Djs
    Base64URL decoded = This is a hash created using the header + payload + secret key.Ensures the token wasn’t tampered with.

    
Libraries : jjwt or java-jwt
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-api</artifactId>
        <version>0.11.5</version>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-impl</artifactId>
        <version>0.11.5</version>
        <scope>runtime</scope>
    </dependency>
    <dependency>
        <groupId>io.jsonwebtoken</groupId>
        <artifactId>jjwt-jackson</artifactId>
        <version>0.11.5</version>
        <scope>runtime</scope>
    </dependency>


Flow diagram:

## 🔐 JWT Authentication Flow

sequenceDiagram
    participant U as User
    participant C as AuthController
    participant AM as AuthenticationManager
    participant UDS as UserDetailsService
    participant DB as Database
    participant JWT as JwtUtil
    participant S as SecuredEndpoint

    U->>C: POST /login (username, password)
    C->>AM: UsernamePasswordAuthenticationToken
    AM->>UDS: loadUserByUsername(username)
    UDS->>DB: Fetch user (username, password, roles)
    DB-->>UDS: Return user record
    UDS-->>AM: Return UserDetails
    AM-->>C: Authentication success
    C->>JWT: Generate JWT (username, roles)
    JWT-->>C: JWT token
    C-->>U: Return JWT in response

    U->>S: Request with Authorization: Bearer <JWT>
    S->>JWT: Validate & parse token
    JWT-->>S: Extract username & roles
    S-->>U: Return secured resource




🔑 Login Request Flow (Credentials → JWT)

User submits login request

Endpoint: POST /auth/login

Body:
{
  "username": "user",
  "password": "password"
}


Controller layer

AuthController.login() receives the request.
Creates a UsernamePasswordAuthenticationToken with username + password.
Calls authenticationManager.authenticate(...).
AuthenticationManager

Delegates to Spring Security’s AuthenticationProvider (in this example, the default DaoAuthenticationProvider).
Uses the configured UserDetailsService (here: in-memory users).

Steps:
Loads user details (username, encoded password, roles).
Encodes the incoming password and compares it with stored BCrypt hash.
If match → returns a fully authenticated Authentication object (with principal + roles).
If mismatch → throws BadCredentialsException.

On success
Back in AuthController, we extract:
Username (auth.getName()),
Roles (auth.getAuthorities()).
Pass them to JwtUtil.generateToken(...).

JwtUtil
Builds a signed JWT with:
sub: username
roles: roles list
iat, exp, jti
Signature using secret key (HS256).
Returns token string.

Response to client
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6...",
  "expiresInMs": 3600000
}


Client stores JWT securely (local storage, memory, or cookie).




🔒 Using JWT (Subsequent Requests)

Client sends request
Example: GET /hello

Header:
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...

Security Filter Chain
Request passes through filters.
JwtFilter (custom filter) intercepts.

JwtFilter
Extracts JWT from Authorization header.
Calls jwtUtil.extractUsername() and jwtUtil.extractRoles().

Validates:
Signature correct?
Token not expired?

If valid:
Creates UsernamePasswordAuthenticationToken with username + roles.
Stores it in SecurityContextHolder.
Spring Security Authorization
Now Spring Security knows the request is authenticated.

Applies rules from SecurityConfig:
/auth/login → permitAll
/hello → must be authenticated
Or role-based rules like .hasRole("ADMIN").

Controller executes
If authorized → controller method runs and returns response.
If not → Spring Security responds with 403 Forbidden.
