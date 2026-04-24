package com.loyalty.identity_service.config;

import com.loyalty.identity_service.entity.AdminUser;
import com.loyalty.identity_service.entity.TenantRegistry;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final RSAKey rsaJwk;
    private final AppProperties appProperties;

    /**
     * Generate an RS256-signed JWT access token with all spec claims.
     */
    public String generateAccessToken(AdminUser user, TenantRegistry tenant,
            List<String> roles, List<String> permissions,
            List<UUID> brandScope, List<UUID> storeScope) {
        try {
            Instant now = Instant.now();
            Instant exp = now.plus(Duration.ofMinutes(appProperties.getJwt().getAccessTokenExpiryMinutes()));

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(appProperties.getJwt().getIssuer())
                    .audience(appProperties.getJwt().getAudience())
                    .subject(user.getId().toString())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(exp))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("tenant_id", tenant.getId().toString())
                    .claim("tenant_slug", tenant.getSlug())
                    .claim("roles", roles)
                    .claim("permissions", permissions)
                    .claim("brand_scope",
                            brandScope != null ? brandScope.stream().map(UUID::toString).toList() : List.of())
                    .claim("store_scope",
                            storeScope != null ? storeScope.stream().map(UUID::toString).toList() : List.of())
                    .build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .keyID(rsaJwk.getKeyID())
                    .type(JOSEObjectType.JWT)
                    .build();

            SignedJWT signedJWT = new SignedJWT(header, claims);
            signedJWT.sign(new RSASSASigner(rsaJwk));

            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Failed to sign JWT", e);
        }
    }

    /**
     * Parse and validate a JWT token (used by /auth/me).
     * Returns the claims if valid, throws exception otherwise.
     */
    public JWTClaimsSet parseAndValidateToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            RSAPublicKey publicKey = rsaJwk.toRSAPublicKey();
            JWSVerifier verifier = new RSASSAVerifier(publicKey);

            if (!signedJWT.verify(verifier)) {
                throw new RuntimeException("Invalid JWT signature");
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            // Check expiration
            if (claims.getExpirationTime() != null && claims.getExpirationTime().before(new Date())) {
                throw new RuntimeException("JWT has expired");
            }

            // Check issuer
            if (!appProperties.getJwt().getIssuer().equals(claims.getIssuer())) {
                throw new RuntimeException("Invalid JWT issuer");
            }

            return claims;
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException("Invalid JWT token", e);
        }
    }

    /**
     * Return JWKS JSON containing the public key(s).
     */
    public Map<String, Object> getJwks() {
        JWKSet jwkSet = new JWKSet(rsaJwk.toPublicJWK());
        return jwkSet.toJSONObject();
    }

    /**
     * Extract user ID (sub claim) from token.
     */
    public UUID extractUserId(String token) {
        JWTClaimsSet claims = parseAndValidateToken(token);
        return UUID.fromString(claims.getSubject());
    }

    public int getAccessTokenExpirySeconds() {
        return appProperties.getJwt().getAccessTokenExpiryMinutes() * 60;
    }
}