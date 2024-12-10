package pt.unl.fct.dstp.crypto;

import pt.unl.fct.common.Utils;
import pt.unl.fct.common.crypto.IntegrityCheck;

import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

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

public class DstpIntegrityCheck implements IntegrityCheck {
    private MacMode macMode;
    private MessageDigest hash;
    private Mac mac;
    private Key hMacKey;
    private final boolean isMac;

    public DstpIntegrityCheck(boolean isMac, String hashAlgorithm, String macAlgorithm, String macKey) throws GeneralSecurityException {
        this.isMac = isMac;
        if (isMac) {
            mac = Mac.getInstance(macAlgorithm);
            setMacMode(macAlgorithm);
            setMacKey(macKey);

        }
        else {
            hash = MessageDigest.getInstance(hashAlgorithm);
        }
    }

    @Override
    public byte[] createIntegrityProof(byte[] data, byte[] nonce) throws GeneralSecurityException {
        if (isMac) {
            switch (macMode) {
                case HMAC -> {
                    return mac.doFinal(data);
                }
                case AESGMAC, RC6GMAC, AESGMACFAST, RC6GMACFAST -> {
                    mac.init(hMacKey, new IvParameterSpec(Utils.fitToSize(nonce, 12)));
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
    }

    private void setMacMode(String value) {
        if (value.equals(MacMode.AESGMAC.getModeName())) {
            macMode = MacMode.AESGMAC;
        }
        else if (value.equals(MacMode.AESGMACFAST.getModeName())) {
            macMode = MacMode.AESGMACFAST;
        }
        else if (value.equals(MacMode.RC6GMAC.getModeName())) {
            macMode = MacMode.RC6GMAC;
        }
        else if (value.equals(MacMode.RC6GMACFAST.getModeName())) {
            macMode = MacMode.RC6GMACFAST;
        }
        else {
            macMode = MacMode.HMAC;
        }
    }

    private void setMacKey(String value) throws InvalidKeyException {
        switch (macMode) {
            case HMAC -> {
                hMacKey =  new SecretKeySpec(Utils.hexStringToByteArray(value), mac.getAlgorithm());
                mac.init(hMacKey);
            }
            case AESGMAC, AESGMACFAST -> {
                hMacKey =  new SecretKeySpec(Utils.hexStringToByteArray(value), "AES");
            }
            case RC6GMAC, RC6GMACFAST -> {
                hMacKey =  new SecretKeySpec(Utils.hexStringToByteArray(value), "RC6");
            }
            default -> {
                throw new IllegalStateException("Invalid MAC mode");
            }
        }
    }

    @Override
    public int getIntegrityProofSize() {
        if (isMac) {
            return mac.getMacLength();
        } else {
            return hash.getDigestLength();
        }
    }

    @Override
    public boolean isMac() {
        return isMac;
    }


}
