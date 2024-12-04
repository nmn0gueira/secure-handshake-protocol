package pt.unl.fct.common.crypto;

import java.security.*;
import java.security.spec.InvalidKeySpecException;

public interface AsymmetricCipher {

    byte[] encrypt(byte[] data, PublicKey publicKey) throws GeneralSecurityException;
    byte[] decrypt(byte[] encryptedData, PrivateKey privateKey) throws GeneralSecurityException;
}
