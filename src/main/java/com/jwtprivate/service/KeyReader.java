package com.jwtprivate.service;

import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Component
public class KeyReader {

    public static PrivateKey getPrivateKey(String filePath) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        BufferedReader reader = new BufferedReader(new FileReader(filePath));
        StringBuilder keyBuilder = new StringBuilder();
        String line;
        boolean isPrivateKey = false;

        while ((line = reader.readLine()) != null) {
            if (line.contains("BEGIN RSA PRIVATE KEY") || isPrivateKey) {
                isPrivateKey = true;
                if (!line.contains("BEGIN RSA PRIVATE KEY") && !line.contains("END RSA PRIVATE KEY")) {
                    keyBuilder.append(line);
                }
                if (line.contains("END RSA PRIVATE KEY")) {
                    break;
                }
            }
        }
        reader.close();

        String privateKeyPEM = keyBuilder.toString();
        byte[] encoded = Base64.getMimeDecoder().decode(privateKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return keyFactory.generatePrivate(keySpec);
    }


    public static PublicKey getPublicKey(String filePath) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        BufferedReader reader = new BufferedReader(new FileReader(filePath));
        StringBuilder keyBuilder = new StringBuilder();
        String line;
        boolean isPublicKey = false;

        while ((line = reader.readLine()) != null) {
            if (line.contains("BEGIN PUBLIC KEY") || isPublicKey) {
                isPublicKey = true;
                if (!line.contains("BEGIN PUBLIC KEY") && !line.contains("END PUBLIC KEY")) {
                    keyBuilder.append(line);
                }
                if (line.contains("END PUBLIC KEY")) {
                    break;
                }
            }
        }
        reader.close();

        String publicKeyPEM = keyBuilder.toString();
        byte[] encoded = Base64.getMimeDecoder().decode(publicKeyPEM);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return keyFactory.generatePublic(keySpec);
    }
}
