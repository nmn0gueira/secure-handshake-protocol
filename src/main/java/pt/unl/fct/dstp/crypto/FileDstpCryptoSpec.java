package pt.unl.fct.dstp.crypto;

import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

/**
 * This class is responsible for loading the crypto configuration from a file. Agreed upon crypto configuration
 */
public class FileDstpCryptoSpec extends DstpCryptoSpec {

    public FileDstpCryptoSpec(String cryptoConfigFile) {
        loadCryptoConfigFromFile(cryptoConfigFile);
        finalizeInitialization();
    }

    private void loadCryptoConfigFromFile(String cryptoConfigFile) {
        try {
            BufferedReader reader = new BufferedReader(new FileReader(cryptoConfigFile));
            String line;
            while ((line = reader.readLine()) != null) {
                processConfigLine(line);
            }
            reader.close();
        } catch (IOException e) {
            LOGGER.severe("Error reading crypto config file: " + e.getMessage());
            throw new RuntimeException(e);
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
            case CONFIDENTIALITY, SYMMETRIC_KEY, SYMMETRIC_KEY_SIZE, IV, IV_SIZE -> symmetricConfig.put(config, value);
            case INTEGRITY, H, MAC, MAC_KEY, MAC_KEY_SIZE -> integrityConfig.put(config, value);
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
                symmetricCipher = new DstpSymmetricCipher(cipher, key, iv, secureRandom);
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

}
