# JWTAuthentication

Authentication is the process of verifying the identity of a user, device, or system to ensure that access is granted only to authorized entities. This critical security step protects sensitive information, systems, and resources from unauthorized use or access.

API Authentication includes secures data exchange between software applications using methods like API keys, OAuth tokens, or JSON Web Tokens (JWTs).

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

```mermaid
sequenceDiagram
    participant U as User (Client)
    participant C as AuthController
    participant AM as AuthenticationManager
    participant UDS as UserDetailsService
    participant P as PasswordEncoder (BCrypt)
    participant J as JwtUtil
    participant F as JwtFilter
    participant S as Spring Security
    participant H as HelloController (Protected API)

    %% --- LOGIN FLOW ---
    U->>C: POST /auth/login (username, password)
    C->>AM: authenticate(UsernamePasswordAuthenticationToken)
    AM->>UDS: loadUserByUsername(username)
    UDS-->>AM: UserDetails (username, hashed password, roles)
    AM->>P: match(raw password, hashed password)
    P-->>AM: match = true/false
    alt credentials valid
        AM-->>C: Authentication (principal, roles)
        C->>J: generateToken(username, roles)
        J-->>C: JWT (signed with secret, exp, roles)
        C-->>U: { "token": "eyJhbGciOi..." }
    else invalid credentials
        AM-->>C: AuthenticationException
        C-->>U: 401 Unauthorized
    end

    %% --- SUBSEQUENT REQUESTS WITH TOKEN ---
    U->>F: GET /hello with "Authorization: Bearer <JWT>"
    F->>J: validate(token), extract username & roles
    alt token valid
        J-->>F: username, roles
        F->>S: SecurityContextHolder.setAuthentication()
        S->>H: forward request (user authenticated)
        H-->>U: Response (Hello user!)
    else token invalid/expired
        J-->>F: error
        F-->>U: 403 Forbidden / 401 Unauthorized
    end


