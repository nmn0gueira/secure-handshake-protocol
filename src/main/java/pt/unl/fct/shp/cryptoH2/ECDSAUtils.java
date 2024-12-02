package pt.unl.fct.shp.cryptoH2;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class ECDSAUtils {

    static {
        Security.addProvider(new BouncyCastleProvider());
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
    public static byte[] sign(PrivateKey privateKey, byte[] message) throws Exception {
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
    public static boolean verify(PublicKey publicKey, byte[] message, byte[] signature) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withECDSA", "BC");
        verifier.initVerify(publicKey);
        verifier.update(message);
        return verifier.verify(signature);
    }

    // Method to load private key from byte array (DER encoded)
    public static ECPrivateKey loadPrivateKey(byte[] privateKeyBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return (ECPrivateKey) keyFactory.generatePrivate(keySpec);
    }

    // Method to load public key from byte array (DER encoded)
    public static ECPublicKey loadPublicKey(byte[] publicKeyBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA", "BC");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        return (ECPublicKey) keyFactory.generatePublic(keySpec);
    }
}
