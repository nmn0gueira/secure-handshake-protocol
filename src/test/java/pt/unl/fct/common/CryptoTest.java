package pt.unl.fct.common;

import org.junit.Test;
import pt.unl.fct.dstp.DstpCryptoSpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.assertEquals;

public class CryptoTest {

    private static final String DEFAULT_CRYPTO_CONFIG_FILE = "cryptoconfig.txt";

    @Test
    public void testAlgorithm() {
        DstpCryptoSpec dstpCryptoSpec1 = new DstpCryptoSpec(DEFAULT_CRYPTO_CONFIG_FILE);
        assertEquals("AES", dstpCryptoSpec1.getAlgorithm());
    }

    @Test
    public void testKeySize() {
        String key = "2a619240bb2d5acfcbcb47387ba80174c0934326d683ad20ef388e7e5150d26e";
        byte[] keyBytes = Utils.hexStringToByteArray(key);
        assertEquals(32, keyBytes.length);
    }

    @Test
    public void testIVSize(){
        String iv = "78f3f700feb3c9aa2c38639983c590b6";
        byte[] ivBytes = Utils.hexStringToByteArray(iv);
        assertEquals(16, ivBytes.length);
    }

    @Test
    public void testCipherInit() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        String key = "2a619240bb2d5acfcbcb47387ba80174c0934326d683ad20ef388e7e5150d26e";
        byte[] keyBytes = Utils.hexStringToByteArray(key);
        String iv = "78f3f700feb3c9aa2c38639983c590b6";
        byte[] ivBytes = Utils.hexStringToByteArray(iv);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"), new javax.crypto.spec.IvParameterSpec(ivBytes));
    }

    // Testes com sizes invalidos para chaves e IVs
}
