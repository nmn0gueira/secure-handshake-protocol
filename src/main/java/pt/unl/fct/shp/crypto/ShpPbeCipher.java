package pt.unl.fct.shp.crypto;

import pt.unl.fct.common.crypto.SymmetricCipher;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class ShpPbeCipher implements SymmetricCipher {

    private static final Cipher PBE_CIPHER;
    private static final SecretKeyFactory PBE_KEY_FACTORY;

    static {
        try {
            PBE_CIPHER = Cipher.getInstance("PBEWithHmacSHA256AndAES_128");
            PBE_KEY_FACTORY = SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_128");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    private final SecretKey key;
    private final byte[] salt;
    private final int iterationCount;

    public ShpPbeCipher(String password, byte[] salt, int iterationCount) throws InvalidKeySpecException {
        this.key = PBE_KEY_FACTORY.generateSecret(new PBEKeySpec(password.toCharArray(), salt, iterationCount));
        this.salt = salt;
        this.iterationCount = iterationCount;
    }

    @Override
    public byte[] encrypt(byte[] data) throws GeneralSecurityException {
        PBE_CIPHER.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount));
        return PBE_CIPHER.doFinal(data);
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) throws GeneralSecurityException {
        PBE_CIPHER.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount));
        return PBE_CIPHER.doFinal(encryptedData);
    }
}
