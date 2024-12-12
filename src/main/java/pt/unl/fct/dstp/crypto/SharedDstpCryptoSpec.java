package pt.unl.fct.dstp.crypto;

import javax.crypto.NoSuchPaddingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Crypto configuration obtained through a secure channel
 */
public class SharedDstpCryptoSpec extends DstpCryptoSpec {

    private final byte[] sharedSecret;

    public SharedDstpCryptoSpec(String cryptoConfig, byte[] sharedSecret) {
        this.sharedSecret = sharedSecret;
        loadCryptoConfigShared(cryptoConfig);
        finalizeInitialization();
    }

    private void loadCryptoConfigShared(String cryptoConfig) {
        String[] lines = cryptoConfig.split("\n");
        for (String line : lines) {
            processConfigLine(line);
        }
    }

    private void processConfigLine(String line) {
        String[] parts = line.split(":");
        if (parts.length != 2) {    // Invalid line (whitespace, empty line, etc.)
            return;
        }
        String key = parts[0].trim();
        String value = parts[1].trim();

        if (value.equals("NULL")) {
            return;
        }

        CryptoConfig config = CryptoConfig.valueOf(key);
        switch (config) {
            case CONFIDENTIALITY -> symmetricConfig.put(config, value);
            case INTEGRITY, H, MAC -> integrityConfig.put(config, value);
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
            try {
                symmetricCipher = new DstpSymmetricCipher(cipher, sharedSecret, secureRandom);
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
            try {
                integrityCheck = new DstpIntegrityCheck(isMac, hashAlgorithm, macAlgorithm, sharedSecret);
            } catch (GeneralSecurityException e) {
                LOGGER.severe("Error initializing integrity check: " + e.getMessage());
                throw new RuntimeException(e);
            }
        }
    }
}

