package pt.unl.fct.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import pt.unl.fct.common.Utils;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class CryptoUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static final SecureRandom SECURE_RANDOM = new SecureRandom();

    /**
     * Gera um par de chaves Diffie-Hellman.
     *
     * @return KeyPair gerado
     * @throws Exception Em caso de falha na geração das chaves
     */
    public static KeyPair generateDHKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
        keyPairGenerator.initialize(2048);  // Usando 2048 bits para segurança
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Obtém o número público Diffie-Hellman (Ydh-client) gerado a partir do par de chaves.
     *
     * @param keyPair O par de chaves Diffie-Hellman gerado
     * @return A chave pública como um array de bytes
     */
    public static byte[] generateYdhClient(KeyPair keyPair) throws Exception {
        PublicKey publicKey = keyPair.getPublic();

        // Verificando se a chave pública é do tipo DHPublicKey
        System.out.println("Tipo de chave pública: " + publicKey.getClass().getName());  // Depuração
    }

    /**
     * Gera um par de chaves ECC usando a curva secp256k1.
     *
     * @return O par de chaves gerado
     * @throws Exception Em caso de falha na geração das chaves
     */
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        keyPairGenerator.initialize(ecSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Gera uma assinatura digital para a mensagem fornecida.
     *
     * @param privateKey A chave privada para assinar
     * @param message    A mensagem a ser assinada
     * @return A assinatura gerada como array de bytes
     * @throws Exception Em caso de falha na assinatura
     */
    public static byte[] sign(PrivateKey privateKey, byte[] message) throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA256withECDSA", "BC");
        signature.initSign(privateKey, new SecureRandom());
        signature.update(message);
        return signature.sign();
    }

    /**
     * Verifica a assinatura digital.
     *
     * @param publicKey A chave pública correspondente
     * @param message   A mensagem original
     * @param signature A assinatura a ser verificada (em bytes)
     * @return True se a assinatura for válida, False caso contrário
     * @throws Exception Em caso de falha na verificação
     */
    public static boolean verify(PublicKey publicKey, byte[] message, byte[] signature) throws GeneralSecurityException {
        Signature verifier = Signature.getInstance("SHA256withECDSA", "BC");
        verifier.initVerify(publicKey);
        verifier.update(message);
        return verifier.verify(signature);
    }

    public static KeyPair loadKeyPairFromFile(String filePath) throws IOException, GeneralSecurityException {
        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream("filePath");
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        // Read the file content
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

    // Method to load private key from byte array (DER encoded)
    public static ECPrivateKey loadPrivateKey(byte[] privateKeyBytes) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return (ECPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    // Method to load public key from byte array (DER encoded)
    public static ECPublicKey loadPublicKey(byte[] publicKeyBytes) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        return (ECPublicKey) keyFactory.generatePublic(keySpec);
    }

    /**
     * Gera um HMAC a partir dos dados e de uma chave secreta.
     *
     * @param secretKey Chave secreta para o HMAC
     * @param data Dados para os quais o HMAC será gerado
     * @return HMAC gerado como array de bytes
     * @throws NoSuchAlgorithmException Se o algoritmo HMAC não for encontrado
     * @throws InvalidKeyException Se a chave secreta for inválida
     */
    public static byte[] generateHMAC(byte[] secretKey, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");  // Usando HMAC com SHA-256
        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey, "HmacSHA256");
        mac.init(secretKeySpec);
        return mac.doFinal(data);
    }

    private static final String ALGORITHM = "PBEWithHmacSHA256AndAES_128";

    public static byte[] encrypt(byte[] data, String password, byte[] salt, int iterationCount) throws GeneralSecurityException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey key = keyFactory.generateSecret(new PBEKeySpec(password.toCharArray(), salt, iterationCount, 128));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount));
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] encryptedData, String password, byte[] salt, int iterationCount) throws GeneralSecurityException {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey key = keyFactory.generateSecret(new PBEKeySpec(password.toCharArray(), salt, iterationCount, 128));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount));
        return cipher.doFinal(encryptedData);
    }
}
