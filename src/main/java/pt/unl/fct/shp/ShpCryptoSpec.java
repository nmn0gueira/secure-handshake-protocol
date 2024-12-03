package pt.unl.fct.shp;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.unl.fct.common.Utils;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
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

public class ShpCryptoSpec {

    public static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final KeyPairGenerator DIFFIE_HELLMAN_KEY_PAIR_GENERATOR;
    private static final KeyPairGenerator ECDSA_KEY_PAIR_GENERATOR;
    private static final int DIFFIE_HELLMAN_KEY_SIZE = 2048;
    private static final ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
    private static final Signature ECDSA_SIGNATURE;
    private static final Signature ECDSA_VERIFIER;
    private static final KeyFactory ECDSA_KEY_FACTORY;
    private static final Mac HMAC_SHA256;
    private static final SecretKeyFactory PBE_KEY_FACTORY;
    private static final Cipher PBE_CIPHER;

    static {
        Security.addProvider(new BouncyCastleProvider());

        try {
            DIFFIE_HELLMAN_KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance("DH", "BC");
            ECDSA_KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance("ECDSA", "BC");
            ECDSA_SIGNATURE = Signature.getInstance("SHA256withECDSA", "BC");
            ECDSA_VERIFIER = Signature.getInstance("SHA256withECDSA", "BC");
            ECDSA_KEY_FACTORY = KeyFactory.getInstance("ECDSA", "BC");
            HMAC_SHA256 = Mac.getInstance("HMAC-SHA256", "BC");
            PBE_KEY_FACTORY = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
            PBE_CIPHER = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");

            DIFFIE_HELLMAN_KEY_PAIR_GENERATOR.initialize(DIFFIE_HELLMAN_KEY_SIZE);
            ECDSA_KEY_PAIR_GENERATOR.initialize(ecSpec, SECURE_RANDOM);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException |
                 NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public static int SALT_SIZE = 8;
    public static int ITERATION_COUNTER_SIZE = 4;
    public static int NONCE_SIZE = 8;


    /**
     * Generates Diffie-Hellman key pair.
     *
     * @return The generated key pair
     */
    public static KeyPair generateDHKeyPair() {
        return DIFFIE_HELLMAN_KEY_PAIR_GENERATOR.generateKeyPair();
    }

    /**
     * TODO
     *
     * @param keyPair O par de chaves Diffie-Hellman gerado
     * @return A chave pública como um array de bytes
     */
    public static byte[] generateYdhClient(KeyPair keyPair) {
        PublicKey publicKey = keyPair.getPublic();
        // TODO: Implementar a geração do número público Diffie-Hellman como especificado nos slides
        // Verificando se a chave pública é do tipo DHPublicKey
        System.out.println("Tipo de chave pública: " + publicKey.getClass().getName());  // Depuração
        return new byte[0];
    }

    /**
     * Generates an ECC key pair using the secp256k1 curve.
     *
     * @return The generated key pair
     */
    public static KeyPair generateECDSAKeyPair()  {
        return ECDSA_KEY_PAIR_GENERATOR.generateKeyPair();
    }

    /**
     * Generates an ECDSA digital signature.
     *
     * @param privateKey The private key to sign with
     * @param message    The message to be signed
     * @return The generated signature as a byte array
     * @throws InvalidKeyException In case of invalid key
     * @throws SignatureException   In case of signature failure
     */
    public static byte[] sign(PrivateKey privateKey, byte[] message) throws InvalidKeyException, SignatureException {
        ECDSA_SIGNATURE.initSign(privateKey, SECURE_RANDOM);
        ECDSA_SIGNATURE.update(message);
        return ECDSA_SIGNATURE.sign();
    }

    /**
     * Verifies the digital signature.
     *
     * @param publicKey The corresponding public key
     * @param message   The original message
     * @param signature The signature to be verified
     * @return True if the signature is valid, false otherwise
     * @throws InvalidKeyException In case of invalid key
     * @throws SignatureException   In case of signature failure
     */
    public static boolean verify(PublicKey publicKey, byte[] message, byte[] signature) throws InvalidKeyException, SignatureException {
        ECDSA_VERIFIER.initVerify(publicKey);
        ECDSA_VERIFIER.update(message);
        return ECDSA_VERIFIER.verify(signature);
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
                publicKey = loadPublicKey(Utils.hexStringToByteArray(keyData));
            } else
            if (keyType.equals("PrivateKey")) {
                privateKey = loadPrivateKey(Utils.hexStringToByteArray(keyData));
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
                publicKey = loadPublicKey(Utils.hexStringToByteArray(keyData));
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
    public static ECPrivateKey loadPrivateKey(byte[] privateKeyBytes) throws InvalidKeySpecException {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return (ECPrivateKey) ECDSA_KEY_FACTORY.generatePrivate(keySpec);
    }

    /**
     * Method to load public key from byte array (DER encoded)
     * @param publicKeyBytes Public key as byte array
     * @return The loaded public key
     * @throws InvalidKeySpecException In case of invalid key specification
     */
    public static ECPublicKey loadPublicKey(byte[] publicKeyBytes) throws InvalidKeySpecException {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        return (ECPublicKey) ECDSA_KEY_FACTORY.generatePublic(keySpec);
    }

    /**
     * Generates a HMAC using the provided secret key.
     *
     * @param secretKey Secret key for the HMAC
     * @param data Data for which the HMAC will be generated
     * @return The generated HMAC as a byte array
     * @throws InvalidKeyException In case of invalid key
     */
    public static byte[] generateHMAC(byte[] secretKey, byte[] data) throws InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HMAC-SHA256");
        HMAC_SHA256.init(secretKeySpec);
        return HMAC_SHA256.doFinal(data);
    }

    /**
     * Encrypts data using password-based encryption.
     * @param data Data to be encrypted
     * @param password Password to be used for encryption
     * @param salt Salt to be used for encryption
     * @param iterationCount Number of iterations
     * @return The encrypted data as a byte array
     * @throws GeneralSecurityException In case of security error
     */
    public static byte[] encrypt(byte[] data, String password, byte[] salt, int iterationCount) throws GeneralSecurityException {
        SecretKey key = PBE_KEY_FACTORY.generateSecret(new PBEKeySpec(password.toCharArray(), salt, iterationCount, 128));
        PBE_CIPHER.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount));
        return PBE_CIPHER.doFinal(data);
    }

    /**
     * Decrypts data using password-based encryption.
     * @param encryptedData Encrypted data to be decrypted
     * @param password Password to be used for decryption
     * @param salt Salt to be used for decryption
     * @param iterationCount Number of iterations
     * @return The decrypted data as a byte array
     * @throws GeneralSecurityException In case of security error
     */
    public static byte[] decrypt(byte[] encryptedData, String password, byte[] salt, int iterationCount) throws GeneralSecurityException {
        SecretKey key = PBE_KEY_FACTORY.generateSecret(new PBEKeySpec(password.toCharArray(), salt, iterationCount, 128));
        PBE_CIPHER.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount));
        return PBE_CIPHER.doFinal(encryptedData);
    }
}
