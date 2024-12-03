package pt.unl.fct.shp;

import org.bouncycastle.jcajce.provider.symmetric.AES;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.unl.fct.common.Utils;

import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.Cipher;



public class ShpCryptoSpec {

    public static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final KeyPairGenerator DIFFIE_HELLMAN_KEY_PAIR_GENERATOR;
    private static final KeyFactory DIFFIE_HELLMAN_KEY_FACTORY;
    private static final KeyPairGenerator ECDSA_KEY_PAIR_GENERATOR;
    private static final ECGenParameterSpec EC_GEN_PARAMETER_SPEC = new ECGenParameterSpec("secp256k1");
    private static final Signature ECDSA_SIGNATURE;
    private static final Signature ECDSA_VERIFIER;
    private static final KeyFactory ECDSA_KEY_FACTORY;
    private static final Mac HMAC_SHA256;
    private static final MessageDigest SHA256;
    private static final SecretKeyFactory PBE_KEY_FACTORY;
    private static final Cipher PBE_CIPHER;
    private static final Cipher ECC_CIPHER;
    private static final Cipher AES_CIPHER;
    private static final KeyPairGenerator ECC_KEY_PAIR_GENERATOR;
    /*
     * Pre-computed values for the primitive root G and
     * prime number P, that will be used for the dynamic key-agreement
     *
     */
    private static final BigInteger G_512 = new BigInteger(
            "153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7"
                    + "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b"
                    + "410b7a0f12ca1cb9a428cc", 16);
    // Um grande numero primo P
    private static final BigInteger P_512 = new BigInteger(
            "9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387"
                    + "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b"
                    + "f0573bf047a3aca98cdf3b", 16);

    private static final DHParameterSpec DH_PARAMETER_SPEC = new DHParameterSpec(P_512, G_512);

    static {
        Security.addProvider(new BouncyCastleProvider());

        try {
            DIFFIE_HELLMAN_KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance("DH", "BC");
            DIFFIE_HELLMAN_KEY_FACTORY = KeyFactory.getInstance("DH", "BC");
            ECDSA_KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance("ECDSA", "BC");
            ECDSA_SIGNATURE = Signature.getInstance("SHA256withECDSA", "BC");
            ECDSA_VERIFIER = Signature.getInstance("SHA256withECDSA", "BC");
            ECDSA_KEY_FACTORY = KeyFactory.getInstance("ECDSA", "BC");
            HMAC_SHA256 = Mac.getInstance("HMAC-SHA256", "BC");
            SHA256 = MessageDigest.getInstance("SHA-256", "BC");
            PBE_KEY_FACTORY = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
            PBE_CIPHER = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
            ECC_CIPHER = Cipher.getInstance("ECIES", "BC");
            AES_CIPHER = Cipher.getInstance("AES/CBC/PKCS5Padding");
            ECC_KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance("EC", "BC");
            DIFFIE_HELLMAN_KEY_PAIR_GENERATOR.initialize(DH_PARAMETER_SPEC);
            ECDSA_KEY_PAIR_GENERATOR.initialize(EC_GEN_PARAMETER_SPEC, SECURE_RANDOM);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException |
                 NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    public static int SALT_SIZE = 8;
    public static int ITERATION_COUNTER_SIZE = 4;
    public static int NONCE_SIZE = 8;
    public static String REQUEST_CONFIRMATION = "ok";


    /**
     * Generates Diffie-Hellman key pair.
     *
     * @return The generated key pair
     */
    public static KeyPair generateKeyAgreementKeyPair() {
        return DIFFIE_HELLMAN_KEY_PAIR_GENERATOR.generateKeyPair();
    }

    public static KeyAgreement createKeyAgreement() throws NoSuchAlgorithmException, NoSuchProviderException {
        return KeyAgreement.getInstance("DH", "BC");
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

    /**
     * Generates a HMAC using the provided secret key.
     *
     * @param secretKey Secret key for the HMAC
     * @param data Data for which the HMAC will be generated
     * @return The generated HMAC as a byte array
     * @throws InvalidKeyException In case of invalid key
     */
    public static byte[] generateHmac(byte[] secretKey, byte[] data) throws InvalidKeyException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HMAC-SHA256");
        HMAC_SHA256.init(secretKeySpec);
        return HMAC_SHA256.doFinal(data);
    }

    /**
     * Verifies the integrity of the data by comparing the integrity proof with a freshly generated one.
     */
    public static boolean verifyIntegrity(byte[] data, byte[] secretKey, byte[] integrityProof) throws InvalidKeyException {
        byte[] generatedProof = generateHmac(data, secretKey);
        return MessageDigest.isEqual(generatedProof, integrityProof);
    }

    /**
     * Generates a SH256 digest for the provided data.
     *
     * @param data Data for which the HMAC will be generated
     * @return The generated digest as a byte array
     */
    public static byte[] generateHash(byte[] data) {
        return SHA256.digest(data);
    }

    public static int getDigitalSignatureLength() {
        return ECDSA_SIGNATURE.getAlgorithm().length();
    }

    public static int getPublicDiffieHellmanKeyLength() {
        return DH_PARAMETER_SPEC.getP().bitLength();
    }

    public static int getHmacLength() {
        return HMAC_SHA256.getMacLength();
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
    public static byte[] passwordBasedEncryption(byte[] data, String password, byte[] salt, int iterationCount) throws GeneralSecurityException {
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
    public static byte[] passwordBasedDecryption(byte[] encryptedData, String password, byte[] salt, int iterationCount) throws GeneralSecurityException {
        SecretKey key = PBE_KEY_FACTORY.generateSecret(new PBEKeySpec(password.toCharArray(), salt, iterationCount, 128));
        PBE_CIPHER.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount));
        return PBE_CIPHER.doFinal(encryptedData);
    }

    public static byte[] symmetricEncrypt(byte[] data, byte[] key) throws GeneralSecurityException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        AES_CIPHER.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return AES_CIPHER.doFinal(data);
    }
    public static byte[] symmetricDecrypt(byte[] encryptedData, byte[] key) throws GeneralSecurityException {
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        AES_CIPHER.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return AES_CIPHER.doFinal(encryptedData);
    }

    public static KeyPair generateECCKeyPair(){return ECC_KEY_PAIR_GENERATOR.generateKeyPair();
    }
    public static byte[] encryptECC(byte[] data, PublicKey publicKey) throws GeneralSecurityException {
        ECC_CIPHER.init(Cipher.ENCRYPT_MODE, publicKey);
        return ECC_CIPHER.doFinal(data);
    }
    public static byte[] decryptECC(byte[] encryptedData, PrivateKey privateKey)throws GeneralSecurityException{
        ECC_CIPHER.init(Cipher.DECRYPT_MODE, privateKey);
        return ECC_CIPHER.doFinal(encryptedData);
    }

    public static byte[] getIncrementedNonce(byte[] nonce) {
        byte[] incrementedNonce = nonce.clone();
        for (int i = incrementedNonce.length - 1; i >= 0; i--) {
            if (++incrementedNonce[i] != 0) {
                break;
            }
        }
        return incrementedNonce;
    }
}
