package pt.unl.fct.common.crypto;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;

public interface IntegrityCheck {
    byte[] createIntegrityProof(byte[] data, byte[] nonce) throws GeneralSecurityException;
    int getIntegrityProofSize();

    /**
     * Verifies the integrity of the data by comparing the integrity proof with a freshly generated one.
     */
    default boolean verifyIntegrity(byte[] data, byte[] nonce, byte[] integrityProof) throws GeneralSecurityException {
        byte[] generatedProof = createIntegrityProof(data, nonce);
        return MessageDigest.isEqual(generatedProof, integrityProof);
    }

    boolean isMac();
}
