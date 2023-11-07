package com.hsbc.jwe.example;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Demo {
    public static final String SYM_PRIVATE_KEY_UAT = "certs/wechat_symphony_rsa_pair_privatekey.pkcs8";
    public static final String SYM_PRIVATE_KEY_PROD = "certs/wechat_symphony_rsa_pair_PROD_privatekey.pkcs8";

    public static final String HSBC_PUBLIC_KEY_UAT = "certs/CM_publickey.pem";
    public static final String HSBC_PUBLIC_KEY_PROD = "certs/CM_publickey_PROD.pem";

    public static void main (String args[]) throws Exception {

//        // Get cid token and jwe payload:
//        String payloadJson = "{\"data\":{\"smsOneTimePasswordDelivery\":{\"mobileNumber\":\"+33684059239\",\"oneTimePasswordCode\":\"C24AB31920\"},\"externalNetworkType\":\"WECHAT\"}}";
//        String jwe = demoSymToHSBC(payloadJson, getSymphonyPrivateKey(), getHSBCPublicKey());
//        System.out.println(jwe);

//        // Get cid token with empty payload: used for GET
//        String jwe = demoSymToHSBC(null, getSymphonyPrivateKey(), getHSBCPublicKey());
//        System.out.println(jwe);


//        // Decrypt response from HSBC
//        String jwe = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.UXatOBeQCASSxcujbZSIP8joH_DKJBEYi8OCADwa09aka4eJpf08WEBR5CMQ-WoSvkiQLhYG-_6LGAOrYtkTJgDIv-TQGTua-DiUksUQE01Hyh3rVm4IFXJ682vQuzkNrX0A0XHZol3AKpOQZDl_fc565JdnL-Lwo_lUvqBQGjmXVSs-GysbV25L4EER-Iw8Sdtu2Rj2E-Yzc5gIB5H_w9ucxmiks8AauiFgxNho1r0SagVsKD_IHIpSFOQm7sdm43q8eYALolSW3KTX9fCix2qVIqPBWsFfUXof77TNTch_Og1AcSo84ik4tfCT_RjGLn8xm3an1MvWzaUPDcWCMEh1QoPnU4A-GvaK0xrt9vN-uVUTw9XnUOt4aGXQGfGnD9oOI5wWMDh4xA9pLbcXUfsq-AblOzBZ-2TJt6wAv1p2Mb0twIYkAi1nN851FWaQI75lDjKmli6yvEG0ibdzsp7SFv-WgStnuleYog6oSaJYh0BJ26Z74-vSW8DHH164eQ0UBzSKKosaEBdSv6IjEtvSOScLc0Ht9Wgld43iQ3EJWg-uDqUwdUvwHjekGkQdCBEudxLmxVvIGKEZsF0oYYx5OYvuf24qLk3OBNY_qLdVef83oLP7kFutuQ1-ghbIFGIX8Kxdzq3ue0_DBqnxtK2NNoZPdR-Esb80lfdyWEw.8s49FCGdWLPNC8xc.3Vhiew8Gh16Ce3hMMd9WdEafZh9iR3kZlf2YDHkYfybHYJe4sS846_gDwW_pBwTQlVZisKQixuEIJ4gbx7fMzNQJcTS1MMfRADZnHfuc1E11mn1bjescA-beUZfxMSrxxUzLoxyHPNBD3bt4fTUd0PXw0T0nzwzcwlRT39ffqWcbUjiSAfYveABBVHsDx6JXhE7_EhIDKXx-FgVewVcgeCx-pp-k6rP0dDzR2houLAarJepmnIzRAcYSO4Aubbgh4-JLmIwWr_c6WjgjhNRJj1NAhc03_H6QLKDfbddk5bozTf6mke2wZJi7F8n1ZFtKv825HZCF1zV6prS02Xl-qcwkQiElWMNv.xf79AMD_SyJm4rjz8ZwKCQ";
//        demoHSBCDecryption(jwe, getSymphonyPrivateKey());
//        // access token
        String jwe = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.O46bA0c6N4xJn7W3jvK5ilS_4aLyE1eFubGcidS2rffovHRrAEndicnHD0SAYM_w2vVK1hj2WNE_XfzZsY_jE7Q4mrcGSg-kJRT1XHKuQc_TjZqthsOOymUw87ARH2rZhhCEI0Yh6pCCcXXXS5g7dMKDt2cmgPQZSWw0Hfy7OJNjvjSmxiEVaatTBhIrwbDCOygzPK-cUMBgKP-MrpUJWNwZDWzOUqW4ZgSKd2guGocUneuhH5tHpLp7Kpgm2KA1-VUNOFplgJcvXXSvUpoSYUliCw5R5T8dXKzrXD0ijrk7xzgZl2OY0iruyfWili2ZElIc78W7JQk9TMf9MEDzpcbJ4JxwA6CGavva5cybsaugEvP8vAJKhxDm2ABXt95u1DujwJW0gU9JRr3oFsSOF467L3qHZ1FvtxoC3Okqx7qdONCGyuqQEz8ghGbylIH7s5ku9HjsElVdwN9NsChHbPa0jRowGotc3RrXfEA1y3OFyFnN5CjmiL81f1WIGZcJkGvQ5apdVTT1T9S4TiuH3AddGNm6pDIyB7WvCa-qx7ikwXhgNE3g820XLR7ln7VbkB2WbE-nC_BNWocynGzyh6DvOjBZI_Yz2PO1iLUyNmISJ70Tm-Av9d0-IZKl4jAxfhUwmG5xBIFP5JvVItYD3ywcJaQvq9RSQZtWBziddwo.zIOsMP3dzdkog1BS.uUV-BYet3M8dnUBScaMauOhgNq_rlczxj2E6qLKrRJjl6vlaVWHeCCUq1yFf2Ghg2ASzzNDQLJY9WESCzl88lXBBOi0ipoR1fGyYQzclsV2BTpU31hreeWsPhix8wQ33l-2GVqYIm5xN6QtxjIqHr2MfDTRhvxCPqSkV6KWEga8glzNN_WEsXvmXHlD_N09xfuSnQQmJLGJKbtXfNRV8tZZLB7Sox_G3oW3yWkl9REZKBlmaJ-rEMAbjvYRmQDu5X6hCFWMpDEL4v004oUsSeoroPG4fqhsePPdV-8fTCUcWO2jJJbHjcJm0Bd7-6fri_lA2HRVihl3-YuKDz6JisbDcgDd-fvrK.__wZBCWWrNr_amwSRq1j3Q";
        demoHSBCDecryption(jwe, getSymphonyPrivateKey());
//
//        // jsCode authenticate
//        String jwe = "eyJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.exff0DzQkFaBB0kDMniuenop3ybxl7V6L5xv5qjKU5IW0HPvp-bypSD5tsO1hOro3K8I0-Ippft7skBlQzbin9JSTw5soplDD3zNqkrMxNlfGrbpDVh4RGW1H2TxHDjkSSEnvs00s4EbT5LWm701M7v10RtlW_LzM3i56WOWocrJncAi2rlUCnPQpsNjKaBBfGRIvx1bAseo4Gp1321pkoL_--Ze9UXWINeBPVhq2AMIat5RHQEQDhRM1PTGtDh4J_DMwvkuQcnK0ShiZuEgOggvfWXp1P8DxmPMIqukbzGLiDaK-YYtWa6431BtWxk0x9F4xF0BicGuvQ6f9JM26w3WTYrbsRDY6a49xgsZMOsD5T2FwrnI-kD2Wx3hH7u0sPSLCqZm1XzMH-vDLJZZcpBrJaVEI5tYXAnDayRPFMtIXdODPsAkMj8iHTcxAhjS--lf73hnnrt9JeFIMN_AuZXEY5u9JBWYVe2fOWaLV4Sj_-j7MmsAa910icTEa2AbHXh7dllHezk1qrCa3PG8wHBaHByd2MwhzagVTTnWmi2EutLiGX9n07ucCBF3PfgSWYkJS6WWUtnFFHPJF-ma2P-5xKOHVLKlpI79w5IiEbO3NwcWVbmZA0vo7Hn3pr_2qmnIDYp_ULDKHVbY_-vHihI0948gSWgpo_up6CK3cKw.zkzY4Yr63g8uXsFP.8IJYZUuXs0MhZPLJrpcFF1aUIJwMvogTTeFjwiewqwLbtGtV-i0HP5eR-tXWCxyx6yfbTNygkDb0UaddVGtbvXVy_UR1hNqff0eriM_qN7lWlKWVKyd29w-sJr0giL2imQKmRENX2uUiFfvEPase-udjkKYaxgsa6mWiZ0BIj-CAm6Cmz6LFjLX0mIByd1rio3fx2MDfZnXleReNXnUFl1sp3CPZYUADEEpbDHjHQXiqpPtKFZATbZqWARc.bp1IjUsSb5g0Es-nxrSS7g";
//        demoHSBCDecryption(jwe, getSymphonyPrivateKey());



    }

    private static void demoE2E(String payloadJson) throws Exception {
        // generateKeyPair - Symphony
        KeyPairGenerator symphonyKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
        symphonyKeyPairGenerator.initialize(4096);
        KeyPair symphonyKeyPair = symphonyKeyPairGenerator.generateKeyPair();

        //generateKeyPair - HSBC
        KeyPairGenerator hsbcKeyPairGenerator = KeyPairGenerator.getInstance("RSA");
        hsbcKeyPairGenerator.initialize(4096);
        KeyPair hsbcKeyPair = hsbcKeyPairGenerator.generateKeyPair();

        //demo
        String jwe = demoSymToHSBC(payloadJson, symphonyKeyPair.getPrivate(), hsbcKeyPair.getPublic());
        demoHSBCDecryption(jwe, hsbcKeyPair.getPrivate());
    }

    private static String demoSymToHSBC(String payloadJson, PrivateKey symphonyPrivateKey, PublicKey hsbcPublicKey) throws Exception {
        if (payloadJson == null || payloadJson.isEmpty()) {
            // Generate CID token:
            String cidToken = JwsHandler.generateCIDToken(null, (RSAPrivateKey) symphonyPrivateKey);
            System.out.println("CID token: " + cidToken);
            return null;
        } else {
            String jwe = JweRsaEncryptDecrypted.encryptWithoutJws(payloadJson, (RSAPublicKey) hsbcPublicKey);

            System.out.println("Encrypted payload:");
            System.out.println(jwe);

            MessageDigest md = MessageDigest.getInstance("SHA-512");

            byte[] hash = md.digest(jwe.getBytes(StandardCharsets.UTF_8));
            StringBuilder hashPayload = new StringBuilder();
            for (byte b : hash) {
                hashPayload.append(String.format("%02x", b));
            }
            System.out.println("hash payload: " + hashPayload);
            // Generate CID token:
            String cidToken = JwsHandler.generateCIDToken(hashPayload.toString(), (RSAPrivateKey) symphonyPrivateKey);
            System.out.println("CID token: " + cidToken);

            return jwe;
        }
    }

    private static void demoHSBCDecryption(String jwe, PrivateKey privateKey) throws Exception {
        // decrypt payload
        String decrptedStr = new String(JweRsaEncryptDecrypted.decrypt(jwe, privateKey));
        System.out.println("decrypted "+decrptedStr);
    }
    private static PrivateKey getSymphonyPrivateKey() throws NoSuchAlgorithmException, InvalidKeySpecException, URISyntaxException, IOException {
        String privateKeyContent = new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource(SYM_PRIVATE_KEY_UAT).toURI())));

        privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");

        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);


        return privKey;
    }

    private static PublicKey getHSBCPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, URISyntaxException, IOException {
        String publicKeyContent = new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource(HSBC_PUBLIC_KEY_UAT).toURI())));
//        String publicKeyContent = new String(Files.readAllBytes(Paths.get(ClassLoader.getSystemResource("wechat_hsbc_rsa_pair_publickey.pem").toURI())));

        String publicKeyString = publicKeyContent
          .replace("-----BEGIN PUBLIC KEY-----", "")
          .replace("-----END PUBLIC KEY-----", "")
          .replace("\\n", "\n")
          .replaceAll("\\s", "");
        byte[] keyBytes =Base64.getDecoder().decode(publicKeyString.getBytes("UTF-8"));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }



}
