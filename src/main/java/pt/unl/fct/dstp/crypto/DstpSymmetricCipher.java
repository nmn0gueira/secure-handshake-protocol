package pt.unl.fct.dstp.crypto;

import pt.unl.fct.common.Utils;
import pt.unl.fct.common.crypto.HashUtils;
import pt.unl.fct.common.crypto.SymmetricCipher;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

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

enum CipherParamSizes {
    AES("AES", 32, 16),
    BLOWFISH("BLOWFISH", 56, 8),
    CHACHA20("ChaCha20", 32, 0),
    CHACHA20_POLY1305("ChaCha20-Poly1305", 32, 0),
    DES("DES", 8, 8),
    TRIPLE_DES("DESede", 24, 8),
    IDEA("IDEA", 16, 8),
    RC4("RC4", 56, 0),
    RC6("RC6", 32, 16);

    private final String name;
    private final int keySize;
    private final int ivSize;

    CipherParamSizes(String name, int keySize, int ivSize) {
        this.name = name;
        this.keySize = keySize;
        this.ivSize = ivSize;
    }

    public String getName() {
        return name;
    }

    public int getKeySize() {
        return keySize;
    }

    public int getIvSize() {
        return ivSize;
    }

    public static CipherParamSizes permissiveValueOf(String name) {
        for (CipherParamSizes value : values()) {
            if (value.getName().equals(name)) {
                return value;
            }
        }
        return null;
    }
}

public class DstpSymmetricCipher implements SymmetricCipher {

    // Configuration
    private final Cipher cipher;
    private SecretKey key;
    private IvParameterSpec staticIvSpec; // For certain ciphers
    private CipherMode cipherMode;
    private final SecureRandom secureRandom;

    public DstpSymmetricCipher(String cipher, String key, String iv, SecureRandom secureRandom) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.cipher = Cipher.getInstance(cipher);
        setCipherMode(cipher);
        setCipherKey(key);
        setCipherIv(iv);
        this.secureRandom = secureRandom;
    }

    public DstpSymmetricCipher(String cipher, byte[] sharedSecret, SecureRandom secureRandom) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.cipher = Cipher.getInstance(cipher);
        setCipherMode(cipher);
        setCipherKey(sharedSecret);
        setCipherIv(sharedSecret);
        this.secureRandom = secureRandom;
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

    private void setCipherKey(String value) {
        this.key = new SecretKeySpec(Utils.hexStringToByteArray(value), getAlgorithm());
    }

    private void setCipherIv(String value) {
        if (value != null) {
            staticIvSpec = new IvParameterSpec(Utils.hexStringToByteArray(value));
        }
    }

    private void setCipherKey(byte[] sharedSecret) {
        byte[] digest = HashUtils.SHA3_512.digest(sharedSecret);
        String algorithm = getAlgorithm();
        switch (CipherParamSizes.permissiveValueOf(algorithm)) {
            case CipherParamSizes.AES -> this.key = new SecretKeySpec(digest, 0, CipherParamSizes.AES.getKeySize(), algorithm);
            case CipherParamSizes.BLOWFISH -> this.key = new SecretKeySpec(digest, 0, CipherParamSizes.BLOWFISH.getKeySize(), algorithm);
            case CipherParamSizes.CHACHA20 -> this.key = new SecretKeySpec(digest, 0, CipherParamSizes.CHACHA20.getKeySize(), algorithm);
            case CipherParamSizes.CHACHA20_POLY1305 -> this.key = new SecretKeySpec(digest, 0, CipherParamSizes.CHACHA20_POLY1305.getKeySize(), algorithm);
            case CipherParamSizes.DES -> this.key = new SecretKeySpec(digest, 0, CipherParamSizes.DES.getKeySize(), algorithm);
            case CipherParamSizes.TRIPLE_DES -> this.key = new SecretKeySpec(digest, 0, CipherParamSizes.TRIPLE_DES.getKeySize(), algorithm);
            case CipherParamSizes.IDEA -> this.key = new SecretKeySpec(digest, 0, CipherParamSizes.IDEA.getKeySize(), algorithm);
            case CipherParamSizes.RC4 -> this.key = new SecretKeySpec(digest, 0, CipherParamSizes.RC4.getKeySize(), algorithm);
            case CipherParamSizes.RC6 -> this.key = new SecretKeySpec(digest, 0, CipherParamSizes.RC6.getKeySize(), algorithm);
            case null -> throw new IllegalStateException("Invalid algorithm");
        }
    }

    /**
     * Set the IV for the cipher. In this version of the method, the IV is generated from the shared secret.
     * Additionally, the IV is always set unless a stream cipher is used.
     * @param sharedSecret - shared secret used to generate the IV
     */
    private void setCipherIv(byte[] sharedSecret) {
        byte[] digest = HashUtils.SHA3_256.digest(sharedSecret);
        if (cipher.getAlgorithm().contains("ECB")) {    // ECB mode does not require an IV
            staticIvSpec = null;
            return;
        }
        String algorithm = getAlgorithm();
        switch (CipherParamSizes.permissiveValueOf(algorithm)) {
            case CipherParamSizes.AES -> staticIvSpec = new IvParameterSpec(digest, 0, CipherParamSizes.AES.getIvSize());
            case CipherParamSizes.BLOWFISH -> staticIvSpec = new IvParameterSpec(digest, 0, CipherParamSizes.BLOWFISH.getIvSize());
            case CipherParamSizes.DES -> staticIvSpec = new IvParameterSpec(digest, 0, CipherParamSizes.DES.getIvSize());
            case CipherParamSizes.TRIPLE_DES -> staticIvSpec = new IvParameterSpec(digest, 0, CipherParamSizes.TRIPLE_DES.getIvSize());
            case CipherParamSizes.IDEA -> staticIvSpec = new IvParameterSpec(digest, 0, CipherParamSizes.IDEA.getIvSize());
            case CipherParamSizes.RC6 -> staticIvSpec = new IvParameterSpec(digest, 0, CipherParamSizes.RC6.getIvSize());
            case CipherParamSizes.CHACHA20, CipherParamSizes.CHACHA20_POLY1305, CipherParamSizes.RC4 -> staticIvSpec = null;
            case null -> throw new IllegalStateException("Invalid algorithm");
        }
    }

    private String getAlgorithm() {
        return cipher.getAlgorithm().split("/")[0];
    }

    @Override
    public byte[] encrypt(byte[] data) throws GeneralSecurityException {
        if (cipher == null || key == null) {
            throw new IllegalStateException("Cipher or key is not initialized");
        }
        switch (cipherMode) {
            // All these modes require a nonce but use different specs
            case GCM, CHACHA20_POLY1305, CHACHA20 -> {
                byte[] nonce = new byte[12];
                secureRandom.nextBytes(nonce);
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
            default -> throw new IllegalStateException("Cipher mode not set");
        }
    }

    @Override
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
                return Utils.subArray(decryptedData, 0, decryptedData.length - padding);
            }

            case NO_AEAD -> {
                if (staticIvSpec != null) {
                    cipher.init(Cipher.DECRYPT_MODE, key, staticIvSpec);
                } else {
                    cipher.init(Cipher.DECRYPT_MODE, key);
                }
                return cipher.doFinal(encryptedData);
            }
            default -> throw new IllegalStateException("Cipher mode not set");
        }
    }
}
