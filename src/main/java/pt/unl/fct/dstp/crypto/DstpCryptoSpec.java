package pt.unl.fct.dstp.crypto;

import pt.unl.fct.common.crypto.AbstractCryptoSpec;
import pt.unl.fct.common.crypto.IntegrityCheck;
import pt.unl.fct.common.crypto.SymmetricCipher;

import java.security.*;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;


public abstract class DstpCryptoSpec extends AbstractCryptoSpec {

    protected enum CryptoConfig {
        CONFIDENTIALITY,
        INTEGRITY,
        SYMMETRIC_KEY,
        SYMMETRIC_KEY_SIZE,
        IV,
        IV_SIZE,
        MAC,
        MAC_KEY,
        MAC_KEY_SIZE,
        H
    }

    // Configuration
    protected final Map<CryptoConfig, String> symmetricConfig = new HashMap<>();
    protected final Map<CryptoConfig, String> integrityConfig = new HashMap<>();
    protected SymmetricCipher symmetricCipher;
    protected IntegrityCheck integrityCheck;

    protected final Logger LOGGER = Logger.getLogger(this.getClass().getName());

    /**
     * Encrypts data with the chosen algorithm and returns the ciphertext.
     *
     * @param data - data to be encrypted
     * @return encrypted data
     */
    public byte[] encrypt(byte[] data) {
        try {
            return symmetricCipher.encrypt(data);
        } catch (GeneralSecurityException e) {
            LOGGER.severe("Error encrypting data: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * Decrypts the data using the current configuration.
     */
    public byte[] decrypt(byte[] encryptedData) throws GeneralSecurityException {
        return symmetricCipher.decrypt(encryptedData);
    }

    public boolean verifyIntegrity(byte[] data, byte[] nonce, byte[] integrityProof) {
        try {
            return integrityCheck.verifyIntegrity(data, nonce, integrityProof);
        } catch (GeneralSecurityException e) {
            LOGGER.severe("Error verifying integrity: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    /**
     * Creates an integrity proof for the data using either HMAC or a hash function, depending on the configuration.
     */
    public byte[] createIntegrityProof(byte[] data, byte[] nonce) {
        try {
            return integrityCheck.createIntegrityProof(data, nonce);
        } catch (GeneralSecurityException e) {
            LOGGER.severe("Error creating integrity proof: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    public int getIntegrityProofSize() {
        return integrityCheck.getIntegrityProofSize();
    }

    public boolean usesMac() {
        return integrityCheck.isMac();
    }
}
