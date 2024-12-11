package pt.unl.fct.shp.crypto;

import pt.unl.fct.common.crypto.SymmetricCipher;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

public class ShpSharedKeyCipher implements SymmetricCipher {

    private final Cipher aesCipher;
    private final SecretKeySpec secretKeySpec;
    private final IvParameterSpec ivParameterSpec;


    public ShpSharedKeyCipher(byte[] key, byte[] iv) {
        try {
            this.aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
        this.secretKeySpec = new SecretKeySpec(key, "AES");
        this.ivParameterSpec = new IvParameterSpec(iv);
    }

    @Override
    public byte[] encrypt(byte[] data) throws GeneralSecurityException {
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        return aesCipher.doFinal(data);
    }

    @Override
    public byte[] decrypt(byte[] data) throws GeneralSecurityException{
        aesCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        return aesCipher.doFinal(data);
    }
}
