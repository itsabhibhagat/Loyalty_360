package com.loyalty.identity_service.service.impl;

import com.loyalty.identity_service.entity.AdminUser;
import com.loyalty.identity_service.entity.RefreshToken;
import com.loyalty.identity_service.entity.TenantRegistry;
import com.loyalty.identity_service.repository.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.OffsetDateTime;
import java.util.*;

import static com.loyalty.identity_service.service.impl.RefreshTokenServiceImpl.sha256Hex;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceImplTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks
    private RefreshTokenServiceImpl service;

    private AdminUser user;
    private TenantRegistry tenant;

    @BeforeEach
    void init() {
        user = new AdminUser();
        user.setId(UUID.randomUUID());

        tenant = new TenantRegistry();
        tenant.setId(UUID.randomUUID());
    }

    //  ISSUE TOKEN

    @Test
    void shouldIssueTokenAndSaveInDb() {
        UUID family = UUID.randomUUID();

        String rawToken = service.issueRefreshToken(
                user, tenant, family, "127.0.0.1", "JUnit"
        );

        assertNotNull(rawToken);
        assertFalse(rawToken.isEmpty());

        ArgumentCaptor<RefreshToken> captor =
                ArgumentCaptor.forClass(RefreshToken.class);

        verify(refreshTokenRepository).save(captor.capture());

        RefreshToken saved = captor.getValue();

        assertEquals(user, saved.getUser());
        assertEquals(tenant.getId(), saved.getTenantId());
        assertEquals(family, saved.getTokenFamily());
        assertNotNull(saved.getTokenHash());
        assertNotNull(saved.getExpiresAt());
    }
    //Token Uniqueness
    @Test
    void shouldGenerateUniqueTokensEachTime() {
        when(refreshTokenRepository.save(any()))
                .thenAnswer(inv -> inv.getArgument(0));

        String token1 = service.issueRefreshToken(user, tenant, UUID.randomUUID(), "ip", "ua");
        String token2 = service.issueRefreshToken(user, tenant, UUID.randomUUID(), "ip", "ua");

        assertNotEquals(token1, token2);
    }

    //SHOULD NOT STORE RAW TOKEN
    @Test
    void shouldStoreHashedTokenNotRaw() {
        ArgumentCaptor<RefreshToken> captor =
                ArgumentCaptor.forClass(RefreshToken.class);

        when(refreshTokenRepository.save(captor.capture()))
                .thenAnswer(inv -> inv.getArgument(0));

        String rawToken = service.issueRefreshToken(
                user, tenant, UUID.randomUUID(), "ip", "agent"
        );

        RefreshToken saved = captor.getValue();

        String expectedHash = RefreshTokenServiceImpl.sha256Hex(rawToken);

        assertEquals(expectedHash, saved.getTokenHash());
        assertNotEquals(rawToken, saved.getTokenHash());
    }

    // VALIDATE TOKEN

    @Test
    void shouldReturnTokenWhenValid() {
        String raw = "valid";
        String hash = sha256Hex(raw);

        RefreshToken token = new RefreshToken();
        token.setTokenHash(hash);
        token.setExpiresAt(OffsetDateTime.now().plusDays(1));

        when(refreshTokenRepository.findByTokenHashAndRevokedAtIsNull(hash))
                .thenReturn(Optional.of(token));

        RefreshToken result = service.validateAndGetToken(raw);

        assertEquals(token, result);
    }

    @Test
    void shouldReturnNullWhenTokenIsExpired() {
        String raw = "expired";
        String hash = sha256Hex(raw);

        RefreshToken token = new RefreshToken();
        token.setTokenHash(hash);
        token.setExpiresAt(OffsetDateTime.now().minusDays(1));

        when(refreshTokenRepository.findByTokenHashAndRevokedAtIsNull(hash))
                .thenReturn(Optional.of(token));

        RefreshToken result = service.validateAndGetToken(raw);

        assertNull(result);
    }

    @Test
    void shouldReturnNullWhenTokenNotFound() {
        String raw = "notfound";
        String hash = sha256Hex(raw);

        when(refreshTokenRepository.findByTokenHashAndRevokedAtIsNull(hash))
                .thenReturn(Optional.empty());

        when(refreshTokenRepository.findByTokenHash(hash))
                .thenReturn(Optional.empty());

        RefreshToken result = service.validateAndGetToken(raw);

        assertNull(result);
    }

    @Test
    void shouldDetectTheftAndRevokeFamily() {
        String raw = "reused";
        String hash = sha256Hex(raw);

        UUID family = UUID.randomUUID();

        RefreshToken usedToken = new RefreshToken();
        usedToken.setTokenHash(hash);
        usedToken.setTokenFamily(family);
        usedToken.setReplacedByTokenId(UUID.randomUUID());

        when(refreshTokenRepository.findByTokenHashAndRevokedAtIsNull(hash))
                .thenReturn(Optional.empty());

        when(refreshTokenRepository.findByTokenHash(hash))
                .thenReturn(Optional.of(usedToken));

        when(refreshTokenRepository.findByTokenFamily(family))
                .thenReturn(List.of(usedToken));

        service.validateAndGetToken(raw);

        verify(refreshTokenRepository).saveAll(anyList());
    }

    //  ROTATE TOKEN

    @Test
    void shouldRotateTokenProperly() {
        RefreshToken oldToken = new RefreshToken();
        oldToken.setId(UUID.randomUUID());
        oldToken.setTokenFamily(UUID.randomUUID());

        RefreshToken newToken = new RefreshToken();
        newToken.setId(UUID.randomUUID());

        when(refreshTokenRepository.findByTokenHash(any()))
                .thenReturn(Optional.of(newToken));

        String newRaw = service.rotateToken(
                oldToken, user, tenant, "ip", "agent"
        );

        assertNotNull(newRaw);
        assertEquals("ROTATED", oldToken.getRevokeReason());
        assertNotNull(oldToken.getRevokedAt());
        assertEquals(newToken.getId(), oldToken.getReplacedByTokenId());
    }

    @Test
    void shouldKeepSameTokenFamilyOnRotation() {
        ArgumentCaptor<RefreshToken> captor =
                ArgumentCaptor.forClass(RefreshToken.class);

        when(refreshTokenRepository.save(captor.capture()))
                .thenAnswer(inv -> inv.getArgument(0));

        when(refreshTokenRepository.findByTokenHash(any()))
                .thenReturn(Optional.of(new RefreshToken()));

        UUID family = UUID.randomUUID();

        RefreshToken oldToken = new RefreshToken();
        oldToken.setTokenFamily(family);

        service.rotateToken(oldToken, user, tenant, "ip", "agent");

        RefreshToken newToken = captor.getAllValues().get(0);

        assertEquals(family, newToken.getTokenFamily());
    }

    //Ignore Unknown token
    @Test
    void shouldIgnoreUnknownTokenDuringRevoke() {
        String raw = "unknown";
        String hash = RefreshTokenServiceImpl.sha256Hex(raw);

        when(refreshTokenRepository.findByTokenHash(hash))
                .thenReturn(Optional.empty());

        assertDoesNotThrow(() -> service.revokeToken(raw));

        verify(refreshTokenRepository, never()).save(any());
    }

    //  REVOKE TOKEN

    @Test
    void shouldRevokeTokenIfExists() {
        String raw = "logout";
        String hash = sha256Hex(raw);

        RefreshToken token = new RefreshToken();
        token.setTokenHash(hash);

        when(refreshTokenRepository.findByTokenHash(hash))
                .thenReturn(Optional.of(token));

        service.revokeToken(raw);

        assertEquals("LOGOUT", token.getRevokeReason());
        assertNotNull(token.getRevokedAt());
    }

    @Test
    void shouldNotAllowRevokedToken() {
        String raw = "token";
        String hash = sha256Hex(raw);

        when(refreshTokenRepository.findByTokenHashAndRevokedAtIsNull(hash))
                .thenReturn(Optional.empty()); // because revoked

        when(refreshTokenRepository.findByTokenHash(hash))
                .thenReturn(Optional.of(new RefreshToken())); // exists but revoked

        RefreshToken result = service.validateAndGetToken(raw);

        assertNull(result);
    }

    @Test
    void shouldNotTriggerTheftForLogoutRevokedToken() {
        String raw = "logoutToken";
        String hash = RefreshTokenServiceImpl.sha256Hex(raw);

        RefreshToken token = new RefreshToken();
        token.setTokenHash(hash);
        token.setTokenFamily(UUID.randomUUID());
        token.setRevokedAt(OffsetDateTime.now());
        token.setRevokeReason("LOGOUT");
        token.setReplacedByTokenId(null); // important

        when(refreshTokenRepository.findByTokenHashAndRevokedAtIsNull(hash))
                .thenReturn(Optional.empty());

        when(refreshTokenRepository.findByTokenHash(hash))
                .thenReturn(Optional.of(token));

        RefreshToken result = service.validateAndGetToken(raw);

        assertNull(result);
        verify(refreshTokenRepository, never()).saveAll(anyList()); // no family revoke
    }

    @Test
    void shouldDoNothingIfTokenNotFound() {
        String raw = "missing";
        String hash = sha256Hex(raw);

        when(refreshTokenRepository.findByTokenHash(hash))
                .thenReturn(Optional.empty());

        service.revokeToken(raw);

        verify(refreshTokenRepository, never()).save(any());
    }

    //  REVOKE FAMILY

    @Test
    void shouldRevokeAllTokensInFamily() {
        UUID family = UUID.randomUUID();

        RefreshToken t1 = new RefreshToken();
        RefreshToken t2 = new RefreshToken();

        when(refreshTokenRepository.findByTokenFamily(family))
                .thenReturn(List.of(t1, t2));

        service.revokeFamily(family);

        assertEquals("THEFT", t1.getRevokeReason());
        assertEquals("THEFT", t2.getRevokeReason());
        assertNotNull(t1.getRevokedAt());
        assertNotNull(t2.getRevokedAt());

        verify(refreshTokenRepository).saveAll(anyList());
    }

    //  HASH VALIDATION

    @Test
    void shouldGenerateValidSha256Hash() {
        String hash = sha256Hex("test");

        assertNotNull(hash);
        assertEquals(64, hash.length());
    }
}