package io.loyalty360.edge_gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Spring Cloud Gateway filter that:
 * 1. Strips any externally-submitted spoofable X-Headers (prevents client
 * tampering)
 * 2. Extracts claims from the validated JWT
 * 3. Injects them as trusted HTTP headers for downstream services
 */
@Component
public class InjectTrustedHeadersGatewayFilterFactory
        extends AbstractGatewayFilterFactory<InjectTrustedHeadersGatewayFilterFactory.Config> {

    private static final String[] TRUSTED_HEADERS = {
            "X-User-Id", "X-Tenant-Id", "X-Tenant-Slug",
            "X-Roles", "X-Permissions", "X-Brand-Scope", "X-Store-Scope"
    };

    public InjectTrustedHeadersGatewayFilterFactory() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> exchange.getPrincipal()
                .filter(principal -> principal instanceof JwtAuthenticationToken)
                .cast(JwtAuthenticationToken.class)
                .map(JwtAuthenticationToken::getToken)
                .flatMap(jwt -> {
                    // Create a mutable copy of the original headers but without the spoofable ones
                    org.springframework.http.HttpHeaders safeHeaders = new org.springframework.http.HttpHeaders();
                    exchange.getRequest().getHeaders().forEach((k, v) -> {
                        boolean isTrusted = false;
                        for (String th : TRUSTED_HEADERS) {
                            if (th.equalsIgnoreCase(k))
                                isTrusted = true;
                        }
                        if (!isTrusted) {
                            safeHeaders.put(k, v);
                        }
                    });

                    // Inject the verified claims from JWT
                    if (jwt.getSubject() != null) {
                        safeHeaders.set("X-User-Id", jwt.getSubject());
                    }
                    addHeaderIfPresent(safeHeaders, jwt, "tenant_id", "X-Tenant-Id");
                    addHeaderIfPresent(safeHeaders, jwt, "tenant_slug", "X-Tenant-Slug");
                    addListHeaderIfPresent(safeHeaders, jwt, "roles", "X-Roles");
                    addListHeaderIfPresent(safeHeaders, jwt, "permissions", "X-Permissions");
                    addListHeaderIfPresent(safeHeaders, jwt, "brand_scope", "X-Brand-Scope");
                    addListHeaderIfPresent(safeHeaders, jwt, "store_scope", "X-Store-Scope");

                    // Use a decorator to return the new headers safely
                    org.springframework.http.server.reactive.ServerHttpRequest decoratedRequest = new org.springframework.http.server.reactive.ServerHttpRequestDecorator(
                            exchange.getRequest()) {
                        @Override
                        public org.springframework.http.HttpHeaders getHeaders() {
                            return safeHeaders;
                        }
                    };

                    return chain.filter(exchange.mutate().request(decoratedRequest).build());
                })
                .switchIfEmpty(chain.filter(exchange)); // If not authenticated, pass through
    }

    private void addHeaderIfPresent(org.springframework.http.HttpHeaders headers, Jwt jwt,
                                    String claimName, String headerName) {
        Object claim = jwt.getClaim(claimName);
        if (claim != null) {
            headers.set(headerName, String.valueOf(claim));
        }
    }

    @SuppressWarnings("unchecked")
    private void addListHeaderIfPresent(org.springframework.http.HttpHeaders headers, Jwt jwt,
                                        String claimName, String headerName) {
        Object claim = jwt.getClaim(claimName);
        if (claim instanceof List) {
            List<String> list = (List<String>) claim;
            if (!list.isEmpty()) {
                headers.set(headerName, String.join(",", list));
            }
        }
    }

    public static class Config {
        // Empty config — no configuration properties needed
    }
}
