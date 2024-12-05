package pt.unl.fct.shp;

import org.junit.Test;
import pt.unl.fct.common.Utils;
import pt.unl.fct.common.crypto.CryptoUtils;
import pt.unl.fct.shp.crypto.ShpCryptoSpec;

import java.security.KeyPair;
import java.security.Security;

public class PreGenTest {
    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    @Test
    public void testECDSAKey() {
        // Generate a key pair
        KeyPair keyPair = CryptoUtils.generateECDSAKeyPair();
        System.out.println("Public key: " + Utils.toHex(keyPair.getPublic().getEncoded()));
        System.out.println("Private key: " + Utils.toHex(keyPair.getPrivate().getEncoded()));
    }

    @Test
    public void testPasswordHash() {
        // Test the password hashing
        String password = "password";
        byte[] passwordHash = ShpCryptoSpec.digest(password.getBytes());
        System.out.println("Password: " + Utils.toHex(passwordHash));
    }

    @Test
    public void testSalt() {
        byte[] salt = ShpCryptoSpec.generateShpSalt();
        System.out.println("Salt: " + Utils.toHex(salt));
    }
}
