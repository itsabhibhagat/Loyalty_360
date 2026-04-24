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
        private String issuer;
        private String audience ;
        private int accessTokenExpiryMinutes ;
        private int refreshTokenExpiryDays ;
        private String privateKeyPath;
        private String publicKeyPath ;
        private String keyId;
    }

    @Getter
    @Setter
    public static class Security {
        private int maxFailedAttempts;
        private int lockDurationMinutes;
        private int bcryptStrength;
    }
}