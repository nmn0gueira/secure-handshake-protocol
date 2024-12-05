package pt.unl.fct.common.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.unl.fct.common.Utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class CryptoUtils {
    public static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private static final KeyFactory DIFFIE_HELLMAN_KEY_FACTORY;
    private static final KeyFactory ECDSA_KEY_FACTORY;
    private static final KeyPairGenerator ECDSA_KEY_PAIR_GENERATOR;
    private static final ECGenParameterSpec EC_GEN_PARAMETER_SPEC = new ECGenParameterSpec("secp256k1");

    static {
        Security.addProvider(new BouncyCastleProvider());

        try {
            DIFFIE_HELLMAN_KEY_FACTORY = KeyFactory.getInstance("DH", "BC");
            ECDSA_KEY_FACTORY = KeyFactory.getInstance("ECDSA", "BC");
            ECDSA_KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance("ECDSA", "BC");
            ECDSA_KEY_PAIR_GENERATOR.initialize(EC_GEN_PARAMETER_SPEC, CryptoUtils.SECURE_RANDOM);

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Generates an ECC key pair using the secp256k1 curve. Used for testing purposes and pre-generated keys.
     *
     * @return The generated key pair
     */
    public static KeyPair generateECDSAKeyPair()  {
        return ECDSA_KEY_PAIR_GENERATOR.generateKeyPair();
    }


    /**
     * Loads a key pair from a file.
     * @param filePath The path to the file containing the key pair
     * @return The loaded key pair
     * @throws IOException In case of I/O error
     * @throws GeneralSecurityException In case of security error
     */
    public static KeyPair loadKeyPairFromFile(String filePath) throws IOException, GeneralSecurityException {
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
                publicKey = loadECPublicKey(Utils.hexStringToByteArray(keyData));
            } else
            if (keyType.equals("PrivateKey")) {
                privateKey = loadECPrivateKey(Utils.hexStringToByteArray(keyData));
            }
        }
        if (privateKey == null || publicKey == null) {
            throw new IllegalStateException("Failed to load server key pair.");
        }
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Loads a public key from a file.
     * @param filePath The path to the file containing the public key
     * @return The loaded public key
     * @throws IOException In case of I/O error
     * @throws GeneralSecurityException In case of security error
     */
    public static PublicKey loadPublicKeyFromFile(String filePath) throws IOException, GeneralSecurityException {
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
                publicKey = loadECPublicKey(Utils.hexStringToByteArray(keyData));
            }
        }
        if (publicKey == null) {
            throw new IllegalStateException("Failed to load server public key.");
        }
        return publicKey;
    }

    /**
     * Method to load private key from byte array (DER encoded)
     * @param privateKeyBytes Private key as byte array
     * @return The loaded private key
     * @throws InvalidKeySpecException In case of invalid key specification
     */
    public static ECPrivateKey loadECPrivateKey(byte[] privateKeyBytes) throws InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return (ECPrivateKey) ECDSA_KEY_FACTORY.generatePrivate(keySpec);
    }

    /**
     * Method to load public key from byte array (DER encoded)
     * @param publicKeyBytes Public key as byte array
     * @return The loaded public key
     * @throws InvalidKeySpecException In case of invalid key specification
     */
    public static ECPublicKey loadECPublicKey(byte[] publicKeyBytes) throws InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        return (ECPublicKey) ECDSA_KEY_FACTORY.generatePublic(keySpec);
    }

    public static PublicKey loadDHPublicKey(byte[] publicKeyBytes) throws InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        return DIFFIE_HELLMAN_KEY_FACTORY.generatePublic(keySpec);
    }
}
