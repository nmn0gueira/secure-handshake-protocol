package pt.unl.fct.common.crypto;

import java.security.SecureRandom;
import java.security.Security;

public abstract class AbstractCryptoSpec {
    protected final SecureRandom secureRandom;

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()); // Add BouncyCastle as a provider
    }

    protected AbstractCryptoSpec() {
        secureRandom = new SecureRandom();
    }
}