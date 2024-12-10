package pt.unl.fct.shp.crypto;

import pt.unl.fct.common.Utils;
import pt.unl.fct.common.crypto.*;

import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Logger;


public class ShpCryptoSpec {

    private static final MessageDigest SHA256;
    private static final Logger LOGGER = Logger.getLogger(ShpCryptoSpec.class.getName());

    static {
        try {
            SHA256 = MessageDigest.getInstance("SHA-256", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static final int SALT_SIZE = 8;
    public static final int ITERATION_COUNTER_SIZE = 2;
    public static final int NONCE_SIZE = 16;
    public static final String REQUEST_CONFIRMATION = "OK";
    public static final String FINISH_PROTOCOL = "GO";

    private static final int MIN_ITERATIONS = 10000;
    private static final int MAX_ITERATIONS = 65536;

    private SymmetricCipher pbeCipher;
    private SymmetricCipher sharedKeyCipher;
    private IntegrityCheck integrityCheck;
    private final AsymmetricCipher asymmetricCipher;
    private final DigitalSignature digitalSignature;
    private final CustomKeyAgreement keyAgreement;

    private final KeyPair peerKeyPair;


    public ShpCryptoSpec(String keyPairPath) {
        this.asymmetricCipher = new ShpAsymmetricCipher();
        this.digitalSignature = new ShpDigitalSignature();
        this.keyAgreement = new ShpKeyAgreement();
        try {
            this.peerKeyPair = CryptoUtils.loadKeyPairFromFile(keyPairPath);
        } catch (IOException | GeneralSecurityException e) {
            LOGGER.severe("Error loading key pair from file.");
            throw new RuntimeException(e);
        }

    }

    public void initPbeCipher(String password, byte[] salt, int iterationCount) throws InvalidKeySpecException {
        this.pbeCipher = new ShpPbeCipher(password, salt, iterationCount);
    }

    public void initSharedKeyCipher(byte[] sharedKey) {
        this.sharedKeyCipher = new ShpSharedKeyCipher(sharedKey);
    }

    public void initIntegrityCheck(byte[] key)  {
        try {
            this.integrityCheck = new ShpIntegrityCheck(key);
        } catch (GeneralSecurityException e) {
            LOGGER.severe("Error initializing integrity check.");
            throw new RuntimeException(e);
        }
    }

    /**
     * Generates a shared key using the provided public key. Two-way Diffie-Hellman key exchange is performed.
     * @param publicKey The public key to generate the shared key with
     * @return The generated shared key
     * @throws GeneralSecurityException
     */
    public byte[] generateSharedKey(byte[] publicKey) throws GeneralSecurityException {
        keyAgreement.doPhase(CryptoUtils.loadDHPublicKey(publicKey));
        return this.keyAgreement.generateSecret();
    }

    /**
     * Generates an ECDSA digital signature.
     *
     * @param message    The message to be signed
     * @return The generated signature as a byte array
     * @throws InvalidKeyException In case of invalid key
     * @throws SignatureException   In case of signature failure
     */
    public byte[] sign(byte[] message) throws InvalidKeyException, SignatureException {
        return digitalSignature.sign(peerKeyPair.getPrivate(), message);
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
    public boolean verify(PublicKey publicKey, byte[] message, byte[] signature) throws InvalidKeyException, SignatureException, InvalidKeySpecException {
        return digitalSignature.verify(publicKey, message, signature);
    }

    /**
     * Generates a HMAC using the provided secret key.
     *
     * @param data Data for which the HMAC will be generated
     * @return The generated HMAC as a byte array
     * @throws InvalidKeyException In case of invalid key
     */
    public byte[] createIntegrityProof(byte[] data) throws GeneralSecurityException {
        if (integrityCheck == null) {
            LOGGER.severe("Integrity check not initialized.");
            throw new IllegalStateException();
        }
        return integrityCheck.createIntegrityProof(data, null);
    }

    /**
     * Verifies the integrity of the data by comparing the integrity proof with a freshly generated one.
     */
    public boolean verifyIntegrity(byte[] data, byte[] integrityProof) throws GeneralSecurityException {
        if (integrityCheck == null) {
            LOGGER.severe("Integrity check not initialized.");
            throw new IllegalStateException();
        }
        return integrityCheck.verifyIntegrity(data, null, integrityProof);
    }

    /**
     * Generates a nonce with the first 2 bytes being the iteration counter randomly chosen between MIN_ITERATIONS and MAX_ITERATIONS
     * and the remaining bytes being completely random.
     * @return The generated nonce as a byte array
     */
    public static byte[] generateShpIterationBytes() {
        int iterations = MIN_ITERATIONS + CryptoUtils.SECURE_RANDOM.nextInt(MAX_ITERATIONS - MIN_ITERATIONS);
        // Convert to a 2-byte array
        byte[] iterationBytes = new byte[ITERATION_COUNTER_SIZE];
        iterationBytes[0] = (byte) (iterations >> 8); // High byte
        iterationBytes[1] = (byte) (iterations);

        byte[] nonce = new byte[ShpCryptoSpec.NONCE_SIZE - ShpCryptoSpec.ITERATION_COUNTER_SIZE];
        CryptoUtils.SECURE_RANDOM.nextBytes(nonce);

        return Utils.concat(iterationBytes, nonce);
    }

    public static byte[] generateShpNonce() {
        byte[] nonce = new byte[ShpCryptoSpec.NONCE_SIZE];
        CryptoUtils.SECURE_RANDOM.nextBytes(nonce);
        return nonce;
    }

    /**
     * Generates a SH256 digest for the provided data.
     *
     * @param data Data for which the digest will be generated
     * @return The generated digest as a byte array
     */
    public static byte[] digest(byte[] data) {
        return SHA256.digest(data);
    }

    public byte[] getPublicDiffieHellmanKeyBytes() {
        return keyAgreement.getPublicKey().getEncoded();
    }

    public int getPublicDiffieHellmanKeyLength() {
        return keyAgreement.getPublicKey().getEncoded().length;
    }

    public int getIntegrityProofSize() {
        if (integrityCheck == null) {
            LOGGER.severe("Integrity check not initialized.");
            throw new IllegalStateException();
        }
        return integrityCheck.getIntegrityProofSize();
    }

    /**
     * Encrypts data using password-based encryption.
     * @param data Data to be encrypted
     * @return The encrypted data as a byte array
     * @throws GeneralSecurityException In case of security error
     */
    public byte[] passwordBasedEncrypt(byte[] data) throws GeneralSecurityException {
        if (pbeCipher == null) {
            LOGGER.severe("PBE cipher not initialized.");
            throw new IllegalStateException();
        }
        return pbeCipher.encrypt(data);
    }

    public byte[] passwordBasedEncrypt(byte[] data, String password, byte[] salt, int iterationCount) throws GeneralSecurityException {
        initPbeCipher(password, salt, iterationCount);
        return passwordBasedEncrypt(data);
    }

    /**
     * Decrypts data using password-based encryption.
     * @param encryptedData Encrypted data to be decrypted
     * @return The decrypted data as a byte array
     * @throws GeneralSecurityException In case of security error
     */
    public byte[] passwordBasedDecrypt(byte[] encryptedData) throws GeneralSecurityException {
        if (pbeCipher == null) {
            LOGGER.severe("PBE cipher not initialized.");
            throw new IllegalStateException();
        }
        return pbeCipher.decrypt(encryptedData);
    }

    public byte[] passwordBasedDecrypt(byte[] encryptedData, String password, byte[] salt, int iterationCount) throws GeneralSecurityException {
        initPbeCipher(password, salt, iterationCount);
        return passwordBasedDecrypt(encryptedData);
    }

    public byte[] sharedKeyEncrypt(byte[] data) throws GeneralSecurityException {
        if (sharedKeyCipher == null) {
            LOGGER.severe("Shared key cipher not initialized.");
            throw new IllegalStateException();
        }
        return sharedKeyCipher.encrypt(data);
    }

    public byte[] sharedKeyEncrypt(byte[] data, byte[] sharedKey) throws GeneralSecurityException {
        initSharedKeyCipher(sharedKey);
        return sharedKeyEncrypt(data);
    }

    public byte[] sharedKeyDecrypt(byte[] encryptedData) throws GeneralSecurityException {
        if (sharedKeyCipher == null) {
            LOGGER.severe("Shared key cipher not initialized.");
            throw new IllegalStateException();
        }
        return sharedKeyCipher.decrypt(encryptedData);
    }

    public byte[] asymmetricEncrypt(byte[] data, PublicKey publicKey) throws GeneralSecurityException {
        return asymmetricCipher.encrypt(data, publicKey);

    }
    public byte[] asymmetricDecrypt(byte[] encryptedData) throws GeneralSecurityException{
        return asymmetricCipher.decrypt(encryptedData, peerKeyPair.getPrivate());
    }
}
