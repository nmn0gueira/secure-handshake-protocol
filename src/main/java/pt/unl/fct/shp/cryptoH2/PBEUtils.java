package pt.unl.fct.shp.cryptoH2;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public class PBEUtils {
    private static final String ALGORITHM = "PBEWithHmacSHA256AndAES_128";

    public static byte[] encrypt(byte[] data, String password, byte[] salt, int iterationCount) throws Exception {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey key = keyFactory.generateSecret(new PBEKeySpec(password.toCharArray(), salt, iterationCount, 128));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount));
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] encryptedData, String password, byte[] salt, int iterationCount) throws Exception {
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey key = keyFactory.generateSecret(new PBEKeySpec(password.toCharArray(), salt, iterationCount, 128));
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount));
        return cipher.doFinal(encryptedData);
    }
}