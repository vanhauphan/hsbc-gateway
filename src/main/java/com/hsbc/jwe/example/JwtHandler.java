package com.hsbc.jwe.example;

import com.nimbusds.jose.jwk.RSAKey;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class JwtHandler {

    public static String createJweWithNestedJws(RSAPrivateKey privateKey, RSAPublicKey publickKey, String plaintext) {
        try {
            String jws = JwsHandler.generateJws(plaintext, privateKey);
            return JweHandler.generateJweWithJws(jws, publickKey);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String createJweWithoutJws( RSAPublicKey publickKey, String plaintext) {
        try {

            return JweHandler.generateJweWithoutJws(plaintext, publickKey);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
