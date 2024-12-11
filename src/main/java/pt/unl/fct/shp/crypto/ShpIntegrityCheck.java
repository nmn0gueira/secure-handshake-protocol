package pt.unl.fct.shp.crypto;

import pt.unl.fct.common.crypto.IntegrityCheck;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public class ShpIntegrityCheck implements IntegrityCheck {

    private final Mac hmacSha256;

    public ShpIntegrityCheck(byte[] key) throws GeneralSecurityException {
        try {
            hmacSha256 = Mac.getInstance("HMAC-SHA256", "BC");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        hmacSha256.init(new SecretKeySpec(key, "HMAC-SHA256"));
    }

    @Override
    public byte[] createIntegrityProof(byte[] data, byte[] nonce) throws GeneralSecurityException {
        return hmacSha256.doFinal(data);
    }

    @Override
    public int getIntegrityProofSize() {
        return hmacSha256.getMacLength();
    }

    @Override
    public boolean isMac() {
        return true;
    }
}
