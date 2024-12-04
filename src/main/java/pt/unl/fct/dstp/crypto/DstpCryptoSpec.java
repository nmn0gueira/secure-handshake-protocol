package pt.unl.fct.dstp.crypto;

import pt.unl.fct.common.crypto.IntegrityCheck;
import pt.unl.fct.common.crypto.SymmetricCipher;

import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

enum CryptoConfig {
    CONFIDENTIALITY,
    INTEGRITY,
    SYMMETRIC_KEY,
    SYMMETRIC_KEY_SIZE,
    IV,
    IV_SIZE,
    MAC,
    MAC_KEY,
    MAC_KEY_SIZE,
    H;
}



public class DstpCryptoSpec {

    // Configuration
    private final Map<CryptoConfig, String> symmetricConfig = new HashMap<>();
    private final Map<CryptoConfig, String> integrityConfig = new HashMap<>();
    private SymmetricCipher symmetricCipher;
    private IntegrityCheck integrityCheck;

    private static final Logger LOGGER = Logger.getLogger(DstpCryptoSpec.class.getName());

    public DstpCryptoSpec(String cryptoConfigFile) {
        loadCryptoConfig(cryptoConfigFile);
        finalizeInitialization();
    }

    private void loadCryptoConfig(String cryptoConfigFile) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(cryptoConfigFile));
            String line;
            while ((line = reader.readLine()) != null) {
                // Parse line
                String[] parts = line.split(":");
                if (parts.length == 2) {
                    // Add crypto config
                    addConfig(parts[0], parts[1].trim());
                }
            }
            reader.close();
        } catch (IOException e) {
            LOGGER.severe("Error reading crypto config file: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private void addConfig(String key, String value) {
        if (value.equals("NULL")) {
            return;
        }
        CryptoConfig config = CryptoConfig.valueOf(key);
        switch (config) {
            case CONFIDENTIALITY, SYMMETRIC_KEY, SYMMETRIC_KEY_SIZE, IV, IV_SIZE -> {
                symmetricConfig.put(config, value);
            }
            case INTEGRITY, H, MAC, MAC_KEY, MAC_KEY_SIZE -> {
                integrityConfig.put(config, value);
            }
            default -> {
                LOGGER.severe("Invalid crypto configuration. " + key + " is not be part of a valid configuration.");
                throw new IllegalArgumentException();
            }
        }
    }

    private void finalizeInitialization() {
        // Initialize symmetric encryption
        if (!symmetricConfig.isEmpty()) {
            String cipher = symmetricConfig.get(CryptoConfig.CONFIDENTIALITY);
            String key = symmetricConfig.get(CryptoConfig.SYMMETRIC_KEY);
            String iv = symmetricConfig.get(CryptoConfig.IV);
            try {
                symmetricCipher = new DstpSymmetricCipher(cipher, key, iv);
            } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
                LOGGER.severe("Error initializing symmetric cipher: " + e.getMessage());
                throw new RuntimeException(e);
            }
        }

        // Initialize integrity check
        if (!integrityConfig.isEmpty()) {
            boolean isMac = !integrityConfig.get(CryptoConfig.INTEGRITY).equals("H");
            String hashAlgorithm = integrityConfig.get(CryptoConfig.H);
            String macAlgorithm = integrityConfig.get(CryptoConfig.MAC);
            String macKey = integrityConfig.get(CryptoConfig.MAC_KEY);
            try {
                integrityCheck = new DstpIntegrityCheck(isMac, hashAlgorithm, macAlgorithm, macKey);
            } catch (GeneralSecurityException e) {
                LOGGER.severe("Error initializing integrity check: " + e.getMessage());
                throw new RuntimeException(e);
            }
        }
    }

    /**
     * Encrypts data with the chosen algorithm and returns the ciphertext.
     * If GCM mode is used, ensure GCM parameters are set.
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
