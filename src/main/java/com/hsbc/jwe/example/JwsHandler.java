package com.hsbc.jwe.example;


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import org.apache.commons.codec.digest.DigestUtils;


import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;


//JWS ietf spec https://datatracker.ietf.org/doc/html/rfc7515

public class JwsHandler {
    private static final int JWS_ELEMENTS_COUNT = 3;

    public static String generateCIDToken(String hashPayload, RSAPrivateKey rsaPrivateKey) throws JOSEException {
        JWSSigner signer = new RSASSASigner(rsaPrivateKey);

        OffsetDateTime now = OffsetDateTime.now();
        OffsetDateTime expiration = now.plusDays(1);
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", "Symphony");
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("iat", now.toInstant().getEpochSecond());
        claims.put("aud", "HSBC");
        claims.put("exp", expiration.toInstant().getEpochSecond());
        if (hashPayload != null) {
            claims.put("payload_hash", hashPayload);
            claims.put("payload_hash_alg", "SHA-512");
        }

        JWSObject jwsObject = new JWSObject(
          new JWSHeader.Builder(JWSAlgorithm.RS512).keyID("Symphony").type(JOSEObjectType.JWT).customParam("ver", "1.0").build(),
          new Payload(claims));
        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    public static String generateJws(String plaintext, RSAPrivateKey signingKey) throws JOSEException {
       // RSAKey rsaKey = new RSAKey.Builder(signingKey)).privateKey((RSAPrivateKey)key).build();
        JWSSigner signer = new RSASSASigner(signingKey);



        JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("Symphony").build(),
                new Payload(plaintext));
        jwsObject.sign(signer);

        return jwsObject.serialize();
    }

    public boolean verifyJws(String jws, RSAKey verificationKey) throws JOSEException, ParseException {
        JWSObject jwsObject = JWSObject.parse(jws);
        JWSVerifier verifier = new RSASSAVerifier(verificationKey);
        return jwsObject.verify(verifier);
    }

    public String extractPlaintext(String jws) {
        String base64Payload = jws.split("\\.")[1];
        byte[] payloadBytes = Base64.getDecoder().decode(base64Payload);
        return new String(payloadBytes);
    }

    public boolean hasValidJwsStructure(String jws) {
        return (jws != null) && (jws.split("\\.").length == JWS_ELEMENTS_COUNT);
    }

}
