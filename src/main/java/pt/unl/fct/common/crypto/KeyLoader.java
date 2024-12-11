package pt.unl.fct.common.crypto;

import pt.unl.fct.common.Utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyLoader {

    /**
     * Loads a key pair from a file.
     * @param filePath The path to the file containing the key pair
     * @return The loaded key pair
     * @throws IOException In case of I/O error
     */
    public static KeyPair loadKeyPairFromFile(String filePath, KeyFactory keyFactory) throws IOException {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream(filePath);
        PrivateKey privateKey = null;
        PublicKey publicKey = null;

        assert inputStream != null;
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String line;
        while ((line = reader.readLine()) != null) {
            String[] parts = line.split(":");
            String keyType = parts[0].trim();
            String keyData = parts[1].trim();
            if (keyType.equals("PublicKey")) {
                publicKey = loadPublicKey(Utils.hexStringToByteArray(keyData), keyFactory);
            } else
            if (keyType.equals("PrivateKey")) {
                privateKey = loadPrivateKey(Utils.hexStringToByteArray(keyData), keyFactory);
            }
        }
        if (privateKey == null || publicKey == null) {
            throw new IllegalStateException("Failed to load key pair.");
        }
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Loads a public key from a file.
     * @param filePath The path to the file containing the public key
     * @return The loaded public key
     * @throws IOException In case of I/O error
     */
    public static PublicKey loadPublicKeyFromFile(String filePath, KeyFactory keyFactory) throws IOException {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream(filePath);
        PublicKey publicKey = null;

        assert inputStream != null;
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        String line;
        while ((line = reader.readLine()) != null) {
            String[] parts = line.split(":");
            String keyType = parts[0].trim();
            String keyData = parts[1].trim();
            if (keyType.equals("PublicKey")) {
                publicKey = loadPublicKey(Utils.hexStringToByteArray(keyData), keyFactory);
            }
        }
        if (publicKey == null) {
            throw new IllegalStateException("Failed to load public key.");
        }
        return publicKey;
    }

    /**
     * Method to load private key from byte array (DER encoded)
     * @param privateKeyBytes Private key as byte array
     * @return The loaded private key
     */
    public static PrivateKey loadPrivateKey(byte[] privateKeyBytes, KeyFactory keyFactory) {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        try {
            return keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Method to load public key from byte array (DER encoded)
     * @param publicKeyBytes Public key as byte array
     * @return The loaded public key
     */
    public static PublicKey loadPublicKey(byte[] publicKeyBytes, KeyFactory keyFactory) {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        try {
            return keyFactory.generatePublic(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
}
