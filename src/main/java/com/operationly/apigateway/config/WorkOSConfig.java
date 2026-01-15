package com.operationly.apigateway.config;

import com.workos.WorkOS;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class WorkOSConfig {

    private final WorkOSProperties workOSProperties;

    @Bean
    public WorkOS workOS() {
        return new WorkOS(workOSProperties.getApiKey());
    }
}

