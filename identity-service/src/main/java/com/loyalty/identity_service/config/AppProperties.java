package com.loyalty.identity_service.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "app")
@Getter
@Setter
public class AppProperties {

    private Jwt jwt = new Jwt();
    private Security security = new Security();

    @Getter
    @Setter
    public static class Jwt {
        private String issuer = "https://auth.loyalty360.io";
        private String audience = "admin";
        private int accessTokenExpiryMinutes = 15;
        private int refreshTokenExpiryDays = 14;
        private String privateKeyPath = "classpath:keys/private.pem";
        private String publicKeyPath = "classpath:keys/public.pem";
        private String keyId = "key-2026-04";
    }

    @Getter
    @Setter
    public static class Security {
        private int maxFailedAttempts = 5;
        private int lockDurationMinutes = 3;
        private int bcryptStrength = 12;
    }
}