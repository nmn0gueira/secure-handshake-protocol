package pt.unl.fct.shp.crypto;

import pt.unl.fct.common.crypto.SymmetricCipher;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

public class ShpSharedKeyCipher implements SymmetricCipher {

    private static final Cipher AES_CIPHER;

    static {
        try {
            AES_CIPHER = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    private final SecretKeySpec secretKeySpec;

    public ShpSharedKeyCipher(byte[] key) {
        this.secretKeySpec = new SecretKeySpec(key, "AES");
    }

    @Override
    public byte[] encrypt(byte[] data) throws GeneralSecurityException {
        AES_CIPHER.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        return AES_CIPHER.doFinal(data);
    }

    @Override
    public byte[] decrypt(byte[] data) throws GeneralSecurityException{
        AES_CIPHER.init(Cipher.DECRYPT_MODE, secretKeySpec);
        return AES_CIPHER.doFinal(data);
    }
}
