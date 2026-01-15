package com.operationly.apigateway.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "workos")
public class WorkOSProperties {
    private String apiKey;
    private String clientId;
    private String jwksUri;
}

