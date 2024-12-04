package pt.unl.fct.shp.crypto;

import pt.unl.fct.common.crypto.CryptoUtils;

import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;


public class ShpCryptoSpec {

    private static final KeyPairGenerator DIFFIE_HELLMAN_KEY_PAIR_GENERATOR;
    private static final KeyPairGenerator ECDSA_KEY_PAIR_GENERATOR;
    private static final ECGenParameterSpec EC_GEN_PARAMETER_SPEC = new ECGenParameterSpec("secp256k1");
    private static final Signature ECDSA_SIGNATURE;
    private static final Signature ECDSA_VERIFIER;
    private static final MessageDigest SHA256;

    /*
     * Pre-computed values for the primitive root G and
     * prime number P, that will be used for the dynamic key-agreement
     *
     */
    private static final BigInteger G_512 = new BigInteger(
            "153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7"
                    + "749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b"
                    + "410b7a0f12ca1cb9a428cc", 16);

    private static final BigInteger P_512 = new BigInteger(
            "9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd387"
                    + "44d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94b"
                    + "f0573bf047a3aca98cdf3b", 16);

    private static final DHParameterSpec DH_PARAMETER_SPEC = new DHParameterSpec(P_512, G_512);

    static {
        try {
            DIFFIE_HELLMAN_KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance("DH", "BC");
            ECDSA_KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance("ECDSA", "BC");
            ECDSA_SIGNATURE = Signature.getInstance("SHA256withECDSA", "BC");
            ECDSA_VERIFIER = Signature.getInstance("SHA256withECDSA", "BC");
            SHA256 = MessageDigest.getInstance("SHA-256", "BC");
            DIFFIE_HELLMAN_KEY_PAIR_GENERATOR.initialize(DH_PARAMETER_SPEC);
            ECDSA_KEY_PAIR_GENERATOR.initialize(EC_GEN_PARAMETER_SPEC, CryptoUtils.SECURE_RANDOM);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
    }

    //TODO: A soluçao ao problema de ter que instanciar em vez de usar estaticamente é criar cada component a null e
    // inicializar no primeiro uso o que tambem ajuda com a inicializaçao preguiçosa
    public static int SALT_SIZE = 8;
    public static int ITERATION_COUNTER_SIZE = 4;
    public static int NONCE_SIZE = 8;
    public static String REQUEST_CONFIRMATION = "OK";

    public ShpCryptoSpec() {
    }

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
        ECDSA_SIGNATURE.initSign(privateKey, CryptoUtils.SECURE_RANDOM);
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
     * Generates a HMAC using the provided secret key.
     *
     * @param secretKey Secret key for the HMAC
     * @param data Data for which the HMAC will be generated
     * @return The generated HMAC as a byte array
     * @throws InvalidKeyException In case of invalid key
     */
    public static byte[] createIntegrityProof(byte[] secretKey, byte[] data) throws GeneralSecurityException {
        return (new ShpIntegrityCheck(secretKey)).createIntegrityProof(data, null);
    }

    /**
     * Verifies the integrity of the data by comparing the integrity proof with a freshly generated one.
     */
    public static boolean verifyIntegrity(byte[] data, byte[] secretKey, byte[] integrityProof) throws GeneralSecurityException {
        return (new ShpIntegrityCheck(secretKey)).verifyIntegrity(data, null, integrityProof);
    }

    /**
     * Generates a SH256 digest for the provided data.
     *
     * @param data Data for which the HMAC will be generated
     * @return The generated digest as a byte array
     */
    public static byte[] digest(byte[] data) {
        return SHA256.digest(data);
    }

    public static int getDigitalSignatureLength() {
        return ECDSA_SIGNATURE.getAlgorithm().length();
    }

    public static int getPublicDiffieHellmanKeyLength() {
        return DH_PARAMETER_SPEC.getP().bitLength();
    }

    public static int getIntegrityProofSize() {
        return ShpIntegrityCheck.INTEGRITY_PROOF_SIZE;
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
    public static byte[] passwordBasedEncrypt(byte[] data, String password, byte[] salt, int iterationCount) throws GeneralSecurityException {
        return (new ShpPbeCipher(password, salt, iterationCount)).encrypt(data);
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
    public static byte[] passwordBasedDecrypt(byte[] encryptedData, String password, byte[] salt, int iterationCount) throws GeneralSecurityException {
        return (new ShpPbeCipher(password, salt, iterationCount)).decrypt(encryptedData);
    }

    public static byte[] sharedKeyEncrypt(byte[] data, byte[] key) throws GeneralSecurityException {
        return (new ShpSharedKeyCipher(key)).encrypt(data);
    }

    public static byte[] sharedKeyDecrypt(byte[] encryptedData, byte[] key) throws GeneralSecurityException {
        return (new ShpSharedKeyCipher(key)).decrypt(encryptedData);
    }


    public static byte[] asymmetricEncrypt(byte[] data, PublicKey publicKey) throws GeneralSecurityException {
        return (new ShpAsymmetricCipher()).encrypt(data, publicKey);

    }
    public static byte[] asymmetricDecrypt(byte[] encryptedData, PrivateKey privateKey)throws GeneralSecurityException{
        return (new ShpAsymmetricCipher()).decrypt(encryptedData, privateKey);
    }
}
