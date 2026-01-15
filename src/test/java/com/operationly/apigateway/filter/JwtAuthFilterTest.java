package com.operationly.apigateway.filter;

import com.operationly.apigateway.config.CacheConfig;
import com.operationly.apigateway.model.UserContextDto;
import com.operationly.apigateway.util.TokenValidationUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class JwtAuthFilterTest {

    private MockWebServer mockWebServer;
    private JwtAuthFilter jwtAuthFilter;
    private TokenValidationUtil tokenValidationUtil;
    private CacheManager cacheManager;
    private Cache cache;

    @BeforeEach
    void setUp() throws IOException {
        mockWebServer = new MockWebServer();
        mockWebServer.start();

        tokenValidationUtil = mock(TokenValidationUtil.class);
        cacheManager = mock(CacheManager.class);
        cache = mock(Cache.class);
        when(cacheManager.getCache(CacheConfig.USER_CONTEXT_CACHE)).thenReturn(cache);
    }

    @AfterEach
    void tearDown() throws IOException {
        mockWebServer.shutdown();
    }

    @Test
    void testFilter_ValidToken_CacheHit_SetsHeaders() {
        // Setup
        String token = "valid.token.here";
        String workosUserId = "user_123";
        Claims claims = Jwts.claims().subject(workosUserId).build();

        when(tokenValidationUtil.verifySessionToken(token)).thenReturn(claims);

        UserContextDto userContext = new UserContextDto("101", workosUserId, "test@example.com", "ADMIN", "org_1");
        when(cache.get(workosUserId, UserContextDto.class)).thenReturn(userContext);

        // Mock WebClient (we expect it NOT to be used for cache hit)
        WebClient.Builder webClientBuilder = mock(WebClient.Builder.class);
        WebClient mockWebClient = mock(WebClient.class);
        when(webClientBuilder.build()).thenReturn(mockWebClient);

        jwtAuthFilter = new JwtAuthFilter(tokenValidationUtil, cacheManager, webClientBuilder);

        // Request
        MockServerHttpRequest request = MockServerHttpRequest.get("/test")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(request);
        WebFilterChain chain = mock(WebFilterChain.class);
        when(chain.filter(any())).thenReturn(Mono.empty());

        // Execute
        StepVerifier.create(jwtAuthFilter.filter(exchange, chain))
                .verifyComplete();

        // Verify
        ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
        verify(chain).filter(captor.capture());

        ServerWebExchange mutated = captor.getValue();
        HttpHeaders headers = mutated.getRequest().getHeaders();
        assertEquals("user_123", headers.getFirst("x-workos-user-id"));
        assertEquals("ADMIN", headers.getFirst("x-user-role"));
        assertEquals("101", headers.getFirst("x-user-id"));
        assertEquals("org_1", headers.getFirst("x-org-id"));
        assertEquals("test@example.com", headers.getFirst("x-user-email"));
    }
}
