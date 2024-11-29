package pt.unl.fct.common;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.*;

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

enum CipherMode {
    // Used for most ciphers
    NO_AEAD("No AEAD"),
    //
    MANUAL_PADDING_CBC("CBC/NoPadding"),
    MANUAL_PADDING_ECB("ECB/NoPadding"),
    // Used for all block ciphers that use the GCM mode of operation
    GCM("GCM"),
    // Specific mode used for ChaCha20-Poly1305
    CHACHA20_POLY1305("ChaCha20-Poly1305"),
    // Specific mode used for ChaCha20
    CHACHA20("ChaCha20");

    private final String modeName;

    CipherMode(String algorithm) {
        this.modeName = algorithm;
    }

    public String getModeName() {
        return modeName;
    }
}

enum MacMode {
    // CMACs
    AESGMAC("AESGMAC"),
    RC6GMAC("RC6GMAC"),
    AESGMACFAST("AES-GMAC"),
    RC6GMACFAST("RC6-GMAC"),

    // HMACs (all HMACs are supported in this mode);
    HMAC("hmac");

    private final String modeName;

    MacMode(String modeName) {
        this.modeName = modeName;
    }

    public String getModeName() {
        return modeName;
    }
}

public class CryptoHandler {

    // Configuration
    private Cipher cipher;
    private IvParameterSpec staticIvSpec; // For certain ciphers
    private CipherMode cipherMode;
    private MacMode macMode;
    private SecretKey key;
    private MessageDigest hash;
    private Mac mac;
    private Key hMacKey;
    private boolean usesMac;


    public CryptoHandler(String cryptoConfigFile) {
        Security.addProvider(new BouncyCastleProvider());
        loadCryptoConfig(cryptoConfigFile);
    }

    private void loadCryptoConfig(String cryptoConfigFile) {
        // Load crypto config file
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
            e.printStackTrace();
        }
    }

    private void addConfig(String key, String value) {
        if (value.equals("NULL")) {
            return;
        }

        try {
            switch (CryptoConfig.valueOf(key)) {
                case CONFIDENTIALITY -> {
                    try {
                        cipher = Cipher.getInstance(value);
                        // If aeadEncryption exists, set it
                        setCipherMode(value);
                    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                        e.printStackTrace();
                    }
                }
                case SYMMETRIC_KEY ->   // Cipher must be initialized first
                        this.key = new SecretKeySpec(CommonUtils.hexStringToByteArray(value), getAlgorithm());
                case SYMMETRIC_KEY_SIZE -> {
                    int keyLengthBits = this.key.getEncoded().length * 8;
                    if (keyLengthBits != Integer.parseInt(value))
                        throw new IllegalArgumentException("Symmetric key length mismatch: Specified:" + keyLengthBits + ", Expected:" + value);

                }
                case IV -> staticIvSpec = new IvParameterSpec(CommonUtils.hexStringToByteArray(value));
                case IV_SIZE -> {
                    if (staticIvSpec == null)
                        throw new IllegalStateException("IV not initialized");
                    int ivLengthBits = this.staticIvSpec.getIV().length * 8;
                    if (ivLengthBits != Integer.parseInt(value))
                        throw new IllegalArgumentException("IV length mismatch");
                }
                case INTEGRITY -> {
                    if (value.equals("HMAC")) {
                        usesMac = true;
                    }
                }
                case H -> {
                    try {
                        hash = MessageDigest.getInstance(value);
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    }
                }
                case MAC -> {
                    try {
                        mac = Mac.getInstance(value);
                        setMacMode(value);
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    }

                }
                case MAC_KEY -> // Mac must be initialized first
                        hMacKey = getMacKey(value);
                case MAC_KEY_SIZE -> {
                    int keyLength = hMacKey.getEncoded().length * 8;
                    if (keyLength != Integer.parseInt(value))
                        throw new IllegalArgumentException("MAC Key length mismatch");
                }
            }
        } catch (IllegalArgumentException e) {
            System.out.println(e.getMessage());
            System.err.println("Invalid crypto configuration. " + key + " is not be part of a valid configuration.");
        }

    }

    private void setCipherMode(String value) {
        if (value.contains(CipherMode.GCM.getModeName())) {
            cipherMode = CipherMode.GCM;
        } else if (value.equals(CipherMode.CHACHA20_POLY1305.getModeName())) {
            cipherMode = CipherMode.CHACHA20_POLY1305;
        } else if (value.equals(CipherMode.CHACHA20.getModeName())) {
            cipherMode = CipherMode.CHACHA20;
        } else if (value.contains(CipherMode.MANUAL_PADDING_CBC.getModeName())) {
            cipherMode = CipherMode.MANUAL_PADDING_CBC;
        } else if (value.contains(CipherMode.MANUAL_PADDING_ECB.getModeName())) {
            cipherMode = CipherMode.MANUAL_PADDING_ECB;
        } else {
            cipherMode = CipherMode.NO_AEAD;
        }
    }

    private void setMacMode(String value) {
        if (value.equals(MacMode.AESGMAC.getModeName())) {
            macMode = MacMode.AESGMAC;
        } else if (value.equals(MacMode.RC6GMAC.getModeName())) {
            macMode = MacMode.RC6GMAC;
        } else {
            macMode = MacMode.HMAC;
        }
    }

    public String getAlgorithm() {
        return cipher.getAlgorithm().split("/")[0];
    }

    private SecretKey getMacKey(String value) {
        switch (macMode) {
            case HMAC -> {
                return new SecretKeySpec(CommonUtils.hexStringToByteArray(value), mac.getAlgorithm());
            }
            case AESGMAC -> {
                return new SecretKeySpec(CommonUtils.hexStringToByteArray(value), "AES");
            }
            case RC6GMAC -> {
                return new SecretKeySpec(CommonUtils.hexStringToByteArray(value), "RC6");
            }
            default -> {
                throw new IllegalStateException("Invalid MAC mode");
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
            if (cipher == null || key == null) {
                throw new IllegalStateException("Cipher or key is not initialized");
            }
            switch (cipherMode) {
                // All these modes require a nonce but use different specs
                case GCM, CHACHA20_POLY1305, CHACHA20 -> {
                    byte[] nonce = new byte[12];
                    SecureRandom.getInstance("SHA1PRNG").nextBytes(nonce);
                    if (cipherMode == CipherMode.GCM) {
                        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
                    } else if (cipherMode == CipherMode.CHACHA20_POLY1305) {
                        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
                    } else {
                        cipher.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
                    }
                    byte[] ciphertext = cipher.doFinal(data);
                    byte[] combined = new byte[nonce.length + ciphertext.length];
                    System.arraycopy(nonce, 0, combined, 0, nonce.length);
                    System.arraycopy(ciphertext, 0, combined, nonce.length, ciphertext.length);
                    return combined;
                }

                case MANUAL_PADDING_CBC, MANUAL_PADDING_ECB -> {
                    if (CipherMode.MANUAL_PADDING_CBC == cipherMode && staticIvSpec == null) {
                        throw new IllegalStateException("IV not set for cipher");
                    }
                    int blockSize = cipher.getBlockSize();
                    int padding = blockSize - (data.length % blockSize);
                    byte[] paddedData = new byte[data.length + padding];
                    System.arraycopy(data, 0, paddedData, 0, data.length);
                    for (int i = data.length; i < paddedData.length; i++) {
                        paddedData[i] = (byte) padding;
                    }
                    if (cipherMode == CipherMode.MANUAL_PADDING_CBC) {
                        cipher.init(Cipher.ENCRYPT_MODE, key, staticIvSpec);
                    } else {
                        cipher.init(Cipher.ENCRYPT_MODE, key);
                    }

                    return cipher.doFinal(paddedData);
                }

                case NO_AEAD -> {
                    if (staticIvSpec != null) {
                        cipher.init(Cipher.ENCRYPT_MODE, key, staticIvSpec);
                    } else {
                        cipher.init(Cipher.ENCRYPT_MODE, key);
                    }
                    return cipher.doFinal(data);
                }
                default -> {
                    throw new IllegalStateException("Cipher mode not set");
                }
            }
        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Decrypts the data using the current configuration.
     */
    public byte[] decrypt(byte[] encryptedData) throws GeneralSecurityException {
        if (cipher == null || key == null) {
            throw new IllegalStateException("Cipher or key is not initialized");
        }
        switch (cipherMode) {
            case GCM, CHACHA20_POLY1305, CHACHA20 -> {
                byte[] nonce = new byte[12];
                System.arraycopy(encryptedData, 0, nonce, 0, nonce.length);
                byte[] ciphertext = new byte[encryptedData.length - nonce.length];
                System.arraycopy(encryptedData, nonce.length, ciphertext, 0, ciphertext.length);

                if (cipherMode == CipherMode.GCM) {
                    cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, nonce));
                } else if (cipherMode == CipherMode.CHACHA20_POLY1305) {
                    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));

                }
                return cipher.doFinal(ciphertext);
            }

            case MANUAL_PADDING_CBC, MANUAL_PADDING_ECB -> {
                if (CipherMode.MANUAL_PADDING_CBC == cipherMode && staticIvSpec == null) {
                    throw new IllegalStateException("IV not set for cipher");
                }
                if (cipherMode == CipherMode.MANUAL_PADDING_CBC) {
                    cipher.init(Cipher.DECRYPT_MODE, key, staticIvSpec);
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, key);
                }
                byte[] decryptedData = cipher.doFinal(encryptedData);
                int padding = decryptedData[decryptedData.length - 1];
                return CommonUtils.subArray(decryptedData, 0, decryptedData.length - padding);
            }

            case NO_AEAD -> {
                if (staticIvSpec != null) {
                    cipher.init(Cipher.DECRYPT_MODE, key, staticIvSpec);
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, key);
                }
                return cipher.doFinal(encryptedData);
            }
            default -> {
                throw new IllegalStateException("Cipher mode not set");
            }
        }
    }

    /**
     * Creates an integrity proof for the data using either HMAC or a hash function, depending on the configuration.
     */
    public byte[] createIntegrityProof(byte[] data, byte[] nonce) {
        try {
            if (usesMac) {
                switch (macMode) {
                    case HMAC -> {
                        mac.init(hMacKey);
                        return mac.doFinal(data);
                    }
                    case AESGMAC, RC6GMAC, AESGMACFAST, RC6GMACFAST -> {
                        mac.init(hMacKey, new IvParameterSpec(CommonUtils.toXBytes(nonce, 12)));
                        return mac.doFinal(data);
                    }
                    default -> {
                        return null;
                    }
                }
            }
            else {
                return hash.digest(data);
            }

        } catch (GeneralSecurityException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Verifies the integrity of the data by comparing the integrity proof with a freshly generated one.
     */
    public boolean verifyIntegrity(byte[] data, byte[] nonce, byte[] integrityProof) {
        byte[] generatedProof = createIntegrityProof(data, nonce);
        return MessageDigest.isEqual(generatedProof, integrityProof);
    }

    public int getIntegrityProofLength() {
        if (usesMac) {
            return mac.getMacLength();
        } else {
            return hash.getDigestLength();
        }
    }

    public boolean isUsingHMac() {
        return usesMac;
    }
}
