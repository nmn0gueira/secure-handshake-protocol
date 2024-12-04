package pt.unl.fct.dstp.crypto;

import pt.unl.fct.common.Utils;
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

public class DstpSymmetricCipher implements SymmetricCipher {

    // Configuration
    private final Cipher cipher;
    private final SecretKey key;
    private IvParameterSpec staticIvSpec; // For certain ciphers
    private CipherMode cipherMode;

    public DstpSymmetricCipher(String cipher, String key, String iv) throws NoSuchPaddingException, NoSuchAlgorithmException {
        this.cipher = Cipher.getInstance(cipher);
        setCipherMode(cipher);
        this.key = new SecretKeySpec(Utils.hexStringToByteArray(key), getAlgorithm());
        if (iv != null) {
            staticIvSpec = new IvParameterSpec(Utils.hexStringToByteArray(iv));
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
            default -> {
                throw new IllegalStateException("Cipher mode not set");
            }
        }
    }
}
