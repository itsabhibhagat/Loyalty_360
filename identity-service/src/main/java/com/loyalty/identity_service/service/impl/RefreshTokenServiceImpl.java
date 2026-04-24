package com.loyalty.identity_service.service.impl;

import com.loyalty.identity_service.entity.AdminUser;
import com.loyalty.identity_service.entity.RefreshToken;
import com.loyalty.identity_service.entity.TenantRegistry;
import com.loyalty.identity_service.repository.RefreshTokenRepository;
import com.loyalty.identity_service.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    @Value("${app.jwt.refresh-token-expiry-days:14}")
    private int refreshTokenExpiryDays;

    /**
     * Generate and store a new refresh token for the given user.
     * Returns the raw (unhashed) token to send to the client.
     */
    @Override
    @Transactional
    public String issueRefreshToken(AdminUser user, TenantRegistry tenant,
                                    UUID tokenFamily, String ipAddress, String userAgent) {
        // Generate 48 random bytes, Base64-URL encode
        byte[] randomBytes = new byte[48];
        SECURE_RANDOM.nextBytes(randomBytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);

        // Hash with SHA-256 for storage
        String tokenHash = sha256Hex(rawToken);

        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .tenantId(tenant.getId())
                .tokenHash(tokenHash)
                .tokenFamily(tokenFamily)
                .expiresAt(OffsetDateTime.now().plusDays(refreshTokenExpiryDays))
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .build();

        refreshTokenRepository.save(refreshToken);

        return rawToken;
    }

    /**
     * Validate and rotate a refresh token.
     * Returns the stored token if valid. Handles theft detection.
     */
    @Override
    @Transactional
    public RefreshToken validateAndGetToken(String rawToken) {
        String tokenHash = sha256Hex(rawToken);

        // First try: find an active (non-revoked) token
        var activeToken = refreshTokenRepository.findByTokenHashAndRevokedAtIsNull(tokenHash);

        if (activeToken.isPresent()) {
            RefreshToken token = activeToken.get();

            // Check expiry
            if (token.isExpired()) {
                return null;
            }

            return token;
        }

        // Check if this is a previously used token (theft detection)
        var anyToken = refreshTokenRepository.findByTokenHash(tokenHash);
        if (anyToken.isPresent()) {
            RefreshToken usedToken = anyToken.get();
            if (usedToken.getReplacedByTokenId() != null) {
                // THEFT DETECTED: revoke entire family
                log.warn("Refresh token theft detected for family: {}", usedToken.getTokenFamily());
                revokeFamily(usedToken.getTokenFamily());
            }
        }

        return null;
    }

    /**
     * Rotate a refresh token: mark old as used, issue new one in same family.
     */
    @Override
    @Transactional
    public String rotateToken(RefreshToken oldToken, AdminUser user, TenantRegistry tenant,
                              String ipAddress, String userAgent) {
        // Issue new token in same family
        String newRawToken = issueRefreshToken(user, tenant, oldToken.getTokenFamily(), ipAddress, userAgent);
        String newTokenHash = sha256Hex(newRawToken);

        // Find the newly created token to get its ID
        RefreshToken newToken = refreshTokenRepository.findByTokenHash(newTokenHash).orElseThrow();

        // Mark old token as rotated
        oldToken.setRevokedAt(OffsetDateTime.now());
        oldToken.setRevokeReason("ROTATED");
        oldToken.setReplacedByTokenId(newToken.getId());
        refreshTokenRepository.save(oldToken);

        return newRawToken;
    }

    /**
     * Revoke a single refresh token (for logout).
     */
    @Override
    @Transactional
    public void revokeToken(String rawToken) {
        String tokenHash = sha256Hex(rawToken);
        refreshTokenRepository.findByTokenHash(tokenHash).ifPresent(token -> {
            if (token.getRevokedAt() == null) {
                token.setRevokedAt(OffsetDateTime.now());
                token.setRevokeReason("LOGOUT");
                refreshTokenRepository.save(token);
            }
        });
    }

    /**
     * Revoke all tokens for a user (for deactivation).
     */
    @Override
    @Transactional
    public void revokeAllUserTokens(UUID userId) {
        refreshTokenRepository.revokeAllByUserId(userId, OffsetDateTime.now());
    }

    /**
     * Revoke an entire token family (theft detection).
     */
    @Override
    @Transactional
    public void revokeFamily(UUID tokenFamily) {
        List<RefreshToken> familyTokens = refreshTokenRepository.findByTokenFamily(tokenFamily);
        OffsetDateTime now = OffsetDateTime.now();
        for (RefreshToken token : familyTokens) {
            if (token.getRevokedAt() == null) {
                token.setRevokedAt(now);
                token.setRevokeReason("THEFT");
            }
        }
        refreshTokenRepository.saveAll(familyTokens);
    }

    /**
     * SHA-256 hash of a string, returned as hex.
     */
    public static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1)
                    hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 hashing failed", e);
        }
    }
}
