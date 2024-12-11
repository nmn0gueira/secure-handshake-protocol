package pt.unl.fct.shp.crypto;

import pt.unl.fct.common.crypto.AsymmetricCipher;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ShpAsymmetricCipher implements AsymmetricCipher {

    private final Cipher eccCipher;

    public ShpAsymmetricCipher() {
        try {
            eccCipher = Cipher.getInstance("ECIES", "BC");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] encrypt(byte[] data, PublicKey publicKey) throws GeneralSecurityException {
        eccCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return eccCipher.doFinal(data);
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) throws GeneralSecurityException {
        eccCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return eccCipher.doFinal(encryptedData);
    }
}
