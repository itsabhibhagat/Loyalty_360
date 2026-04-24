package com.loyalty.identity_service.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final GatewayTrustFilter gatewayTrustFilter;

    @Value("${app.security.bcrypt-strength}")
    private int bcryptStrength;

    public SecurityConfig(GatewayTrustFilter gatewayTrustFilter) {
        this.gatewayTrustFilter = gatewayTrustFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // Public routes (Auth & JWKS)
                        .requestMatchers("/auth/**").permitAll()
                        .requestMatchers("/.well-known/**").permitAll()
                        // All /admin routes require authentication
                        .requestMatchers("/admin/**").authenticated()
                        .anyRequest().authenticated())
                // Add custom filter to read X-User-Id and X-Permissions injected by Edge
                // Gateway
                .addFilterBefore(gatewayTrustFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(bcryptStrength);
    }
}
