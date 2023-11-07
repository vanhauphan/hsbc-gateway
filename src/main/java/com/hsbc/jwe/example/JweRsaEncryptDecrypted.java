package com.hsbc.jwe.example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import lombok.Builder;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 *
 * jwe rsa encrypt decrypted
 */
@Builder
public class JweRsaEncryptDecrypted {

    /**
     *
     * @param payload: the request or response body
     * @param publicKey: public key for the encryption
     * @param privateKey: private key for the signature
     * @return
     * @throws Exception
     */
    public static String encrypt(String payload, RSAPrivateKey privateKey,RSAPublicKey publicKey) throws Exception {

        return JwtHandler.createJweWithNestedJws(privateKey,publicKey,payload);
    }
    public static String encryptWithoutJws(String payload,RSAPublicKey publicKey) throws Exception {


        return JwtHandler.createJweWithoutJws(publicKey,payload);
    }

    public static byte[] decrypt(String jwe, PrivateKey privateKey) throws Exception {

//        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
//        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
//        PrivateKey privateKeyInstance = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

        JWEDecrypter decrypter = new RSADecrypter(privateKey);

        JWEObject jweObject = JWEObject.parse(jwe);
        jweObject.decrypt(decrypter);
        Payload payload = jweObject.getPayload();
        return payload.toBytes();
    }

}

