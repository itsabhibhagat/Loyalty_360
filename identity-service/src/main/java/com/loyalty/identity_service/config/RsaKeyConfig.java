package com.loyalty.identity_service.config;

import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Configuration
public class RsaKeyConfig {

    @Value("${app.jwt.private-key-path:#{null}}")
    private Resource privateKeyResource;

    @Value("${app.jwt.public-key-path:#{null}}")
    private Resource publicKeyResource;

    @Value("${app.jwt.key-id:key-2026-04}")
    private String keyId;

    @Bean
    public KeyPair rsaKeyPair() throws Exception {
        if (privateKeyResource != null && privateKeyResource.exists()
                && publicKeyResource != null && publicKeyResource.exists()) {
            RSAPrivateKey privateKey = readPrivateKey(privateKeyResource);
            RSAPublicKey publicKey = readPublicKey(publicKeyResource);
            return new KeyPair(publicKey, privateKey);
        }

        // Generate keys for development (NOT for production)
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    @Bean
    public RSAKey rsaJwk(KeyPair rsaKeyPair) {
        RSAPublicKey publicKey = (RSAPublicKey) rsaKeyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(keyId)
                .build();
    }

    private RSAPrivateKey readPrivateKey(Resource resource) throws Exception {
        String key = readPemContent(resource);
        byte[] decoded = Base64.getDecoder().decode(key);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private RSAPublicKey readPublicKey(Resource resource) throws Exception {
        String key = readPemContent(resource);
        byte[] decoded = Base64.getDecoder().decode(key);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private String readPemContent(Resource resource) throws Exception {
        try (InputStream is = resource.getInputStream()) {
            String content = new String(is.readAllBytes());
            return content
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
        }
    }
}
