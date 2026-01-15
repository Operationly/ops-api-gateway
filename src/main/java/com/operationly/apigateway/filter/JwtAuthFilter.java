package com.operationly.apigateway.filter;

import com.operationly.apigateway.config.CacheConfig;
import com.operationly.apigateway.model.UserContextDto;
import com.operationly.apigateway.util.TokenValidationUtil;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;

import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Collections;

@Slf4j
public class JwtAuthFilter implements WebFilter {

    private final TokenValidationUtil tokenValidationUtil;
    private final CacheManager cacheManager;
    private final WebClient webClient;

    public JwtAuthFilter(TokenValidationUtil tokenValidationUtil,
            CacheManager cacheManager,
            WebClient.Builder webClientBuilder) {
        this.tokenValidationUtil = tokenValidationUtil;
        this.cacheManager = cacheManager;
        this.webClient = webClientBuilder.build();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // If no Authorization header or doesn't start with "Bearer ", pass through
        // The security config will handle 403 if it's a protected route
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return chain.filter(exchange);
        }

        String jwtToken = authHeader.substring(7);

        return Mono.fromCallable(() -> {
            // Verify token using WorkOS service
            log.debug("Verifying JWT token with WorkOS");
            Claims claims = tokenValidationUtil.verifySessionToken(jwtToken);

            // Extract user ID from claims
            String workosUserId = claims.getSubject();
            if (workosUserId == null) {
                workosUserId = claims.get("user_id", String.class);
            }
            log.debug("Token verified successfully for WorkOS User ID: {}", workosUserId);

            return workosUserId;
        })
                .flatMap(workosUserId -> {
                    if (workosUserId != null) {
                        // Always set WorkOS User ID header
                        ServerHttpRequest.Builder requestBuilder = exchange.getRequest().mutate()
                                .header("x-workos-user-id", workosUserId);

                        // Get user context from cache or API and add additional headers
                        return getUserContext(workosUserId)
                                .flatMap(userContextDto -> {
                                    // Add user context headers to the request
                                    ServerHttpRequest request = requestBuilder
                                            .header("x-user-role", userContextDto.getRole())
                                            .header("x-user-id", userContextDto.getUserId())
                                            .header("x-org-id", userContextDto.getOrganizationId())
                                            .header("x-user-email", userContextDto.getEmail())
                                            .build();

                                    // Create authentication token
                                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                            workosUserId,
                                            null,
                                            Collections.emptyList());

                                    // Set authentication in reactive security context and continue with modified
                                    // exchange
                                    ServerWebExchange modifiedExchange = exchange.mutate().request(request).build();
                                    return chain.filter(modifiedExchange)
                                            .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authToken));
                                })
                                .onErrorResume(e -> {
                                    // If user context fetch fails, still continue with just WorkOS User ID header
                                    log.warn("Failed to fetch user context, continuing with WorkOS User ID only: {}",
                                            e.getMessage());

                                    ServerHttpRequest request = requestBuilder.build();
                                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                            workosUserId,
                                            null,
                                            Collections.emptyList());

                                    ServerWebExchange modifiedExchange = exchange.mutate().request(request).build();
                                    return chain.filter(modifiedExchange)
                                            .contextWrite(ReactiveSecurityContextHolder.withAuthentication(authToken));
                                });
                    }
                    return chain.filter(exchange);
                })
                .onErrorResume(e -> {
                    log.error("JWT token verification failed: {}", e.getMessage());
                    // On error, return 401 Unauthorized
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                });
    }

    private Mono<UserContextDto> getUserContext(String workosUserId) {
        Cache cache = cacheManager.getCache(CacheConfig.USER_CONTEXT_CACHE);
        if (cache != null) {
            UserContextDto cachedContext = cache.get(workosUserId, UserContextDto.class);
            if (cachedContext != null) {
                log.debug("Cache hit for user: {}", workosUserId);
                return Mono.just(cachedContext);
            }
        }

        log.debug("Cache miss for user: {}, fetching from user-management", workosUserId);
        return webClient.get()
                .uri("lb://USER-MANAGEMENT/operationly/user-management/api/v1/users/context?workosUserId="
                        + workosUserId)
                .retrieve()
                .bodyToMono(UserContextDto.class)
                .doOnNext(ctx -> {
                    if (cache != null) {
                        cache.put(workosUserId, ctx);
                        log.debug("Cached user context for user: {}", workosUserId);
                    }
                })
                .onErrorResume(e -> {
                    log.error("Failed to fetch user context for workosUserId: {}", workosUserId, e);
                    return Mono.error(e); // Propagate error to trigger 401
                });
    }
}
