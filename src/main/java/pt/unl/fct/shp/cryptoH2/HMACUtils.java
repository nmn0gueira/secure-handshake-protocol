package pt.unl.fct.shp.cryptoH2;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class HMACUtils {
    private static final String ALGORITHM = "HmacSHA256";

    public static byte[] generateHMAC(byte[] data, byte[] key) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
        Mac mac = Mac.getInstance(ALGORITHM);
        mac.init(keySpec);
        return mac.doFinal(data);
    }
}