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
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

public class ShpPbeCipher implements SymmetricCipher {

    private final Cipher pbeCipher;
    private final SecretKey key;
    private final byte[] salt;
    private final int iterationCount;

    public ShpPbeCipher(String password, byte[] salt, int iterationCount) {
        try {
            SecretKeyFactory pbeKeyFactory = SecretKeyFactory.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");

            this.key = pbeKeyFactory.generateSecret(new PBEKeySpec(password.toCharArray()));
            this.pbeCipher = Cipher.getInstance("PBEWITHSHA256AND192BITAES-CBC-BC","BC");

        } catch (InvalidKeySpecException | NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
        this.salt = salt;
        this.iterationCount = iterationCount;
    }

    @Override
    public byte[] encrypt(byte[] data) throws GeneralSecurityException {
        pbeCipher.init(Cipher.ENCRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount));
        return pbeCipher.doFinal(data);
    }

    @Override
    public byte[] decrypt(byte[] encryptedData) throws GeneralSecurityException {
        pbeCipher.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(salt, iterationCount));
        return pbeCipher.doFinal(encryptedData);
    }
}
