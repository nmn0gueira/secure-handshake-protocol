package pt.unl.fct.shp;

import org.junit.Test;
import pt.unl.fct.common.Utils;
import pt.unl.fct.crypto.CryptoUtils;

import java.security.KeyPair;

public class ECDSATest {

    @Test
    public void testECDSAKey() throws Exception {
        // Test the ECDSA signature

        // Generate a key pair
        KeyPair keyPair = CryptoUtils.generateKeyPair();
        System.out.println("Public key: " + Utils.toHex(keyPair.getPublic().getEncoded()));
        System.out.println("Private key: " + Utils.toHex(keyPair.getPrivate().getEncoded()));
    }
}
