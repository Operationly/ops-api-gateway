# Operationly API Gateway

API Gateway service for the Operationly platform, built with Spring Cloud Gateway. This service provides centralized authentication, routing, and request management for all microservices in the Operationly ecosystem.

## Overview

The API Gateway serves as the single entry point for all client requests, handling:
- JWT token verification using WorkOS
- User context management and caching
- Request routing to downstream microservices
- Security and authentication
- Distributed tracing and monitoring

## Architecture

### Key Components

- **Spring Cloud Gateway**: Reactive API gateway for routing and filtering requests
- **Netflix Eureka Client**: Service discovery integration
- **WorkOS Integration**: JWT token verification and user authentication
- **Redis Caching**: User context caching for improved performance
- **Spring Security**: OAuth2 resource server for authentication
- **Micrometer Tracing**: Distributed tracing with Zipkin integration

### Request Flow

1. **Client Request**: Incoming request with JWT token in Authorization header
2. **JWT Verification**: Token verified using WorkOS JWKS endpoint
3. **User Context Retrieval**: 
   - Check Redis cache for user context
   - If cache miss, fetch from user-management service
   - Cache the result for subsequent requests
4. **Header Injection**: Add user context headers to downstream request:
   - `x-workos-user-id`: WorkOS user identifier
   - `x-user-id`: Internal user ID
   - `x-user-role`: User role
   - `x-org-id`: Organization ID
   - `x-user-email`: User email
5. **Route**: Forward authenticated request to target microservice

## Features

### Authentication & Authorization
- JWT token verification using WorkOS
- Signature validation against WorkOS JWKS endpoint
- Configurable whitelisted URLs for public endpoints
- Automatic 401 response for invalid tokens
- Automatic 403 response for missing tokens on protected routes

### Caching
- Redis-backed user context caching
- Reduced latency for authenticated requests
- Configurable cache names and TTL

### Routing
- Dynamic service routing using Eureka service discovery
- Load balancing with `lb://` protocol
- Path-based routing predicates

### Monitoring & Observability
- Spring Boot Actuator endpoints
- Distributed tracing with Zipkin
- Configurable logging levels
- Health checks and metrics

## Technology Stack

- **Java**: 17
- **Spring Boot**: 3.5.9
- **Spring Cloud**: 2025.0.1
- **WorkOS SDK**: 4.18.1
- **JJWT**: 0.13.0
- **Redis**: Distributed caching
- **Maven**: Build tool
- **Lombok**: Code generation

## Prerequisites

- Java 17 or higher
- Maven 3.6+
- Redis server (for caching)
- Eureka server (for service discovery)
- WorkOS account with configured application

## Configuration

### Environment Variables

Required environment variables:

```bash
# WorkOS Configuration
WORKOS_API_KEY=sk_test_xxxxx
WORKOS_CLIENT_ID=client_xxxxx

# Redis Configuration (optional, defaults provided)
REDIS_HOST=localhost
REDIS_PORT=6379
```

### Application Configuration

Key configuration in `application.yaml`:

```yaml
server:
  port: 9090

spring:
  application:
    name: api-gateway
  cache:
    type: redis
    cache-names: userContext
  cloud:
    gateway:
      routes:
        - id: user-management
          uri: lb://USER-MANAGEMENT
          predicates:
            - Path=/operationly/user-management/**

workos:
  api-key: ${WORKOS_API_KEY}
  client-id: ${WORKOS_CLIENT_ID}
  jwks-uri: https://api.workos.com/sso/jwks/${WORKOS_CLIENT_ID}

whitelisted:
  urls:
    - /actuator/**
```

## Setup and Installation

### 1. Clone the Repository

```bash
cd /path/to/operationly
```

### 2. Set Environment Variables

Create a `.env` file or export environment variables:

```bash
export WORKOS_API_KEY=your_workos_api_key
export WORKOS_CLIENT_ID=your_workos_client_id
export REDIS_HOST=localhost
export REDIS_PORT=6379
```

### 3. Build the Application

```bash
mvn clean install
```

### 4. Run the Application

```bash
mvn spring-boot:run
```

Or run the JAR directly:

```bash
java -jar target/ops-api-gateway-0.0.1-SNAPSHOT.jar
```

The gateway will start on port `9090` by default.

## API Routes

### User Management Service

- **Path**: `/operationly/user-management/**`
- **Target**: `lb://USER-MANAGEMENT`
- **Description**: Routes all user management requests to the user-management microservice

### Actuator Endpoints (Public)

- **Path**: `/actuator/**`
- **Description**: Health checks, metrics, and monitoring endpoints
- **Authentication**: Not required (whitelisted)

## Security Configuration

### Protected Routes

By default, all routes except whitelisted URLs require a valid JWT token:
- Token must be provided in `Authorization` header as `Bearer <token>`
- Token is verified against WorkOS JWKS endpoint
- Missing or invalid tokens result in 401 Unauthorized response
- Missing tokens on protected routes result in 403 Forbidden response

### Whitelisted Routes

The following routes are publicly accessible:
- `/actuator/**` - Actuator endpoints

To add more whitelisted routes, update the `whitelisted.urls` configuration in `application.yaml`.

## Development

### Project Structure

```
src/
├── main/
│   ├── java/
│   │   └── com/operationly/apigateway/
│   │       ├── config/
│   │       │   ├── CacheConfig.java
│   │       │   ├── SecurityConfig.java
│   │       │   ├── WebClientConfig.java
│   │       │   ├── WorkOSConfig.java
│   │       │   └── WorkOSProperties.java
│   │       ├── exception/
│   │       │   └── BusinessException.java
│   │       ├── filter/
│   │       │   └── JwtAuthFilter.java
│   │       ├── model/
│   │       │   └── UserContextDto.java
│   │       ├── util/
│   │       │   └── TokenValidationUtil.java
│   │       └── APIGatewayApplication.java
│   └── resources/
│       └── application.yaml
└── test/
    └── java/
        └── com/operationly/apigateway/
            └── filter/
                └── JwtAuthFilterTest.java
```

### Running Tests

```bash
mvn test
```

### Code Style

The project uses:
- Lombok for reducing boilerplate code
- SLF4J for logging
- Spring Boot best practices

## Troubleshooting

### Common Issues

1. **401 Unauthorized Error**
   - Verify JWT token is valid and not expired
   - Check WorkOS configuration (API key and client ID)
   - Ensure JWKS endpoint is accessible

2. **503 Service Unavailable**
   - Verify target microservice is registered with Eureka
   - Check service discovery configuration
   - Ensure target service is running

3. **Redis Connection Error**
   - Verify Redis server is running
   - Check Redis host and port configuration
   - Ensure network connectivity to Redis

4. **Eureka Registration Failed**
   - Verify Eureka server is running
   - Check Eureka server URL in configuration
   - Review network connectivity

## Contributing

1. Create a feature branch from `main`
2. Make your changes
3. Write/update tests
4. Ensure all tests pass
5. Submit a pull request

## License

Proprietary - Operationly Platform

## Support

For issues or questions, please contact the Operationly development team.
