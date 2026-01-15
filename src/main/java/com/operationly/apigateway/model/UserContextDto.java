package com.operationly.apigateway.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserContextDto implements Serializable {
    private String userId;
    private String workosUserId;
    private String email;
    private String role;
    private String organizationId;
}
