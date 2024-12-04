package pt.unl.fct.shp.crypto;

import pt.unl.fct.common.crypto.AsymmetricCipher;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ShpAsymmetricCipher implements AsymmetricCipher {

    private static final Cipher ECC_CIPHER;

    static {
        try {
            ECC_CIPHER = Cipher.getInstance("ECIES", "BC");
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public ShpAsymmetricCipher() {
        // empty
    }


    @Override
    public byte[] encrypt(byte[] data, PublicKey publicKey) throws GeneralSecurityException {
        ECC_CIPHER.init(Cipher.ENCRYPT_MODE, publicKey);
        return ECC_CIPHER.doFinal(data);
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) throws GeneralSecurityException {
        ECC_CIPHER.init(Cipher.DECRYPT_MODE, privateKey);
        return ECC_CIPHER.doFinal(encryptedData);
    }
}
