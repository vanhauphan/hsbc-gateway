package com.hsbc.jwe.example;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

public class JweHandler {
    private static final int JWE_ELEMENTS_COUNT = 5;

    public static String generateJweWithJws(String jws, RSAPublicKey encryptionKey) throws ParseException, JOSEException {
        SignedJWT signedJWT = SignedJWT.parse(jws);
        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .contentType("JWT")
                        .keyID("Symphony")
                        .build(),
                new Payload(signedJWT));
        jweObject.encrypt(new RSAEncrypter(encryptionKey));
        return jweObject.serialize();
    }

    public static String generateJweWithoutJws(String plainText, RSAPublicKey encryptionKey) throws ParseException, JOSEException {

        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                        .contentType("JWT")
                        .keyID("Symphony")
                        .build(),
                new Payload(plainText.getBytes()));
        jweObject.encrypt(new RSAEncrypter(encryptionKey));
        return jweObject.serialize();
    }

    public String extractJws(String jwe, RSAKey decryptionKey) throws ParseException, JOSEException {
        JWEObject jweObject = JWEObject.parse(jwe);
        jweObject.decrypt(new RSADecrypter(decryptionKey));
        SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
        return signedJWT.serialize();
    }

    public boolean hasValidJweStructure(String jwe) {
        return (jwe != null) && (jwe.split("\\.").length == JWE_ELEMENTS_COUNT);
    }
}
