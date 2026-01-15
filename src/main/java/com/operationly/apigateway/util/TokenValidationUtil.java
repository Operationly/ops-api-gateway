package com.operationly.apigateway.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.operationly.apigateway.config.WorkOSProperties;
import com.operationly.apigateway.exception.BusinessException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenValidationUtil {

    private static final int EXPECTED_SIG_LENGTH = 256;
    private static final int POSSIBLE_SIG_LENGTH = 257;
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private final WorkOSProperties workOSProperties;

    // Cache for JWKS keys to avoid frequent network calls
    private final Map<String, PublicKey> keyCache = new ConcurrentHashMap<>();
    private final ObjectMapper mapper = new ObjectMapper();

    /**
     * Verifies the session token and returns the Claims.
     *
     * @param sessionToken The WorkOS session token (JWT)
     * @return The JWT Claims
     * @throws BusinessException If verification fails
     */
    public Claims verifySessionToken(String sessionToken) {
        try {
            // Split the token
            String[] parts = sessionToken.split("\\.");
            if (parts.length != 3) {
                throw new BusinessException("Invalid JWT format");
            }

            // 1. Decode Header to find Key ID
            String kid = getKidFromHeader(parts[0]);

            // 2. Get the signing key
            PublicKey signingKey = getSigningKey(kid);

            // 3. Manually Verify Signature
            verifySignature(parts, signingKey);

            // 4. Parse Body to Claims
            Map<String, Object> claimsMap = parseClaims(parts[1]);

            // 5. Validate Expiration
            validateExpiration(claimsMap);

            // Build Claims object
            return Jwts.claims().add(claimsMap).build();

        } catch (BusinessException e) {
            throw e;
        } catch (Exception e) {
            log.error("Token verification failed: {}", e.getMessage());
            throw new BusinessException("Token verification failed: " + e.getMessage());
        }
    }

    private String getKidFromHeader(String headerPart) throws IOException, BusinessException {
        String headerJson = new String(Base64.getUrlDecoder().decode(headerPart), StandardCharsets.UTF_8);
        JsonNode headerNode = mapper.readTree(headerJson);
        String kid = headerNode.has("kid") ? headerNode.get("kid").asText() : null;

        if (kid == null) {
            throw new BusinessException("JWT header missing 'kid' claim");
        }
        return kid;
    }

    // Corrected retry logic with key re-initialization
    private boolean retryVerify(Signature verifier, PublicKey key, byte[] signatureBytes, byte[] signedContent,
            int srcPos) {
        try {
            byte[] trimmed = new byte[EXPECTED_SIG_LENGTH];
            System.arraycopy(signatureBytes, srcPos, trimmed, 0, EXPECTED_SIG_LENGTH);
            verifier.initVerify(key);
            verifier.update(signedContent);
            return verifier.verify(trimmed);
        } catch (Exception e) {
            log.debug("Strip retry failed: {}", e.getMessage());
            return false;
        }
    }

    // Re-implementing verifySignature to include key for retries
    private void verifySignature(String[] parts, PublicKey signingKey) throws Exception {
        byte[] signedContent = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        byte[] signatureBytes = Base64.getUrlDecoder().decode(parts[2]);

        Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM);
        verifier.initVerify(signingKey);
        verifier.update(signedContent);

        boolean verified = false;
        try {
            verified = verifier.verify(signatureBytes);
        } catch (java.security.SignatureException e) {
            // Ignore
        }

        if (!verified && signatureBytes.length == POSSIBLE_SIG_LENGTH) {
            log.debug("Signature length is {}, trying to strip bytes", POSSIBLE_SIG_LENGTH);
            // Try stripping leading
            if (retryVerify(verifier, signingKey, signatureBytes, signedContent, 1)) {
                log.info("Verification succeeded after stripping leading byte");
                verified = true;
            }
            // Try stripping trailing if still not verified
            else if (retryVerify(verifier, signingKey, signatureBytes, signedContent, 0)) {
                log.info("Verification succeeded after stripping trailing byte");
                verified = true;
            }
        }

        if (!verified) {
            throw new BusinessException("Invalid JWT signature. Length: " + signatureBytes.length);
        }
    }

    private Map<String, Object> parseClaims(String payloadPart) throws JsonProcessingException {
        String payloadJson = new String(Base64.getUrlDecoder().decode(payloadPart), StandardCharsets.UTF_8);
        return mapper.readValue(payloadJson, Map.class);
    }

    private void validateExpiration(Map<String, Object> claimsMap) throws BusinessException {
        if (claimsMap.containsKey("exp")) {
            long exp = ((Number) claimsMap.get("exp")).longValue();
            long now = System.currentTimeMillis() / 1000;
            if (now > exp) {
                throw new BusinessException("Session token has expired");
            }
        } else {
            throw new BusinessException("Session token missing 'exp' claim");
        }
    }

    /**
     * Retrieves the signing key from cache or fetches from WorkOS JWKS.
     */
    private PublicKey getSigningKey(String kid) throws Exception {
        if (keyCache.containsKey(kid)) {
            return keyCache.get(kid);
        }

        // Fetch JWKS
        String jwksUrl = workOSProperties.getJwksUri();
        URL url = new URI(jwksUrl).toURL();

        JsonNode jwksNode = mapper.readTree(url);
        JsonNode keysNode = jwksNode.get("keys");

        if (keysNode != null && keysNode.isArray()) {
            for (JsonNode keyNode : keysNode) {
                if (kid.equals(keyNode.get("kid").asText())) {
                    return parseAndCacheKey(kid, keyNode);
                }
            }
        }

        throw new BusinessException("Matching key not found in JWKS for kid: " + kid);
    }

    private PublicKey parseAndCacheKey(String kid, JsonNode keyNode) throws Exception {
        // Try to get key from x5c certificate first (safer)
        if (keyNode.has("x5c") && keyNode.get("x5c").isArray() && !keyNode.get("x5c").isEmpty()) {
            try {
                String certStr = keyNode.get("x5c").get(0).asText();
                byte[] certBytes = Base64.getDecoder().decode(certStr);
                java.security.cert.CertificateFactory certFactory = java.security.cert.CertificateFactory
                        .getInstance("X.509");
                java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) certFactory
                        .generateCertificate(new java.io.ByteArrayInputStream(certBytes));
                PublicKey key = cert.getPublicKey();
                keyCache.put(kid, key);
                return key;
            } catch (Exception e) {
                log.warn("Failed to parse x5c certificate, falling back to n/e: {}", e.getMessage());
            }
        }

        // Fallback to n/e
        String n = keyNode.get("n").asText();
        String e = keyNode.get("e").asText();

        BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
        BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PublicKey key = factory.generatePublic(spec);

        keyCache.put(kid, key);
        return key;
    }

}
