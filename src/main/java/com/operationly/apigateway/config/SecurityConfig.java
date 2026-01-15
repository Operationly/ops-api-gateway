package com.operationly.apigateway.config;

import com.operationly.apigateway.filter.JwtAuthFilter;
import com.operationly.apigateway.util.TokenValidationUtil;
import org.springframework.cache.CacheManager;
import org.springframework.web.reactive.function.client.WebClient;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

import java.util.List;

@Configuration
@EnableWebFluxSecurity
@ConfigurationProperties(prefix = "whitelisted")
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;

    public SecurityConfig(TokenValidationUtil tokenValidationUtil, CacheManager cacheManager,
            WebClient.Builder webClientBuilder) {
        this.jwtAuthFilter = new JwtAuthFilter(tokenValidationUtil, cacheManager, webClientBuilder);
    }

    @Setter
    private List<String> urls;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(urls != null ? urls.toArray(new String[0]) : new String[0]).permitAll()
                        .anyExchange().authenticated())
                .addFilterAt(jwtAuthFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint((exchange, e) -> {
                            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                            return exchange.getResponse().setComplete();
                        })
                        .accessDeniedHandler((exchange, e) -> {
                            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                            return exchange.getResponse().setComplete();
                        }));

        return http.build();
    }
}
