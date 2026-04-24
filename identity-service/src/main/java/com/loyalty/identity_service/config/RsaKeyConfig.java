package com.loyalty.identity_service.config;

import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import com.loyalty.identity_service.config.AppProperties;

@Configuration
@RequiredArgsConstructor
public class RsaKeyConfig {

    private final AppProperties appProperties;
    private final ResourceLoader resourceLoader;


    @Bean
    public KeyPair rsaKeyPair() throws Exception {
        String privatePath = appProperties.getJwt().getPrivateKeyPath();
        String publicPath = appProperties.getJwt().getPublicKeyPath();

        if (privatePath != null && publicPath != null) {
            Resource privateKeyResource = resourceLoader.getResource(privatePath);
            Resource publicKeyResource = resourceLoader.getResource(publicPath);

            if (privateKeyResource.exists() && publicKeyResource.exists()) {
                RSAPrivateKey privateKey = readPrivateKey(privateKeyResource);
                RSAPublicKey publicKey = readPublicKey(publicKeyResource);
                return new KeyPair(publicKey, privateKey);
            }
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
                .keyID(appProperties.getJwt().getKeyId())
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
